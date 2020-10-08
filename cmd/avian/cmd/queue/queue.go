package queue

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/avian-digital-forensics/auto-processing/generate/ruby"
	api "github.com/avian-digital-forensics/auto-processing/pkg/avian-api"
	"github.com/avian-digital-forensics/auto-processing/pkg/avian-client"
	"github.com/avian-digital-forensics/auto-processing/pkg/powershell"
	"go.uber.org/zap"

	"github.com/jinzhu/gorm"
	ps "github.com/simonjanss/go-powershell"
)

const (
	sleepMinutes = 2
)

type Queue struct {
	db     *gorm.DB
	shell  ps.Shell
	uri    string
	logger *zap.Logger
}

// New returns a new queue
func New(db *gorm.DB, shell ps.Shell, uri string, logger *zap.Logger) Queue {
	return Queue{db: db, shell: shell, uri: uri, logger: logger}
}

func (q *Queue) Start() {
	q.logger.Info("Queue started")
	for {
		q.loop()
		time.Sleep(time.Duration(sleepMinutes * time.Minute))
	}
}

func (q *Queue) loop() {
	q.logger.Debug("Getting runners from queue")
	runners, err := getRunners(q.db)
	if err != nil {
		q.logger.Error("cannot get runners", zap.String("exception", err.Error()))
		return
	}
	q.logger.Debug("Found runners from Queue", zap.Int("amount", len(runners)))

	for _, runner := range runners {
		q.logger.Debug("Trying to start runner", zap.String("runner", runner.Name))

		// check if the runners server is active
		var server api.Server
		query := q.db.Where("active = ? and hostname = ?", false, runner.Hostname)
		if query.First(&server).RecordNotFound() {
			q.logger.Debug("Server is already active", zap.String("runner", runner.Name), zap.String("server", runner.Hostname))
			continue
		}

		// Check to see if licence is active
		nms, err := activeLicence(q.db, runner.Nms, runner.Licence, runner.Workers)
		if err != nil {
			q.logger.Debug("Failed to fetch licence from NMS",
				zap.String("runner", runner.Name),
				zap.String("nms", runner.Nms),
				zap.String("licencetype", runner.Licence),
				zap.String("exception", err.Error()),
			)
			continue
		}

		// create a new run
		run := q.newRun(runner, &server, nms)
		if err := run.setActive(); err != nil {
			q.logger.Error("Cannot set runner to active", zap.String("exception", err.Error()))
			continue
		}

		q.logger.Info("Starting runner",
			zap.String("runner", runner.Name),
			zap.String("server", runner.Hostname),
			zap.String("nms", runner.Nms),
			zap.String("licence", runner.Licence),
			zap.Int("workers", int(runner.Workers)),
		)

		go run.handle(run.start())
	}
}

type run struct {
	queue  *Queue
	runner *api.Runner
	server *api.Server
	nms    *api.Nms
	client *powershell.Client
}

func (q *Queue) newRun(runner *api.Runner, server *api.Server, nms *api.Nms) *run {
	return &run{
		queue:  q,
		runner: runner,
		server: server,
		nms:    nms,
	}
}

func (r *run) setActive() error {
	db := r.queue.db

	// Set runner to active and save to db
	if err := db.Model(&api.Runner{}).Where("id = ?", r.runner.ID).Update("active", true, "healthy_at", time.Now()).Error; err != nil {
		return fmt.Errorf("Failed to set runner to active: %v", err)
	}

	// Set server to active and save to db
	if err := db.Model(&api.Server{}).Where("id = ?", r.server.ID).Update("active", true).Error; err != nil {
		return fmt.Errorf("Failed to set server to active: %v", err)
	}

	// Set new values to NMS
	r.nms.InUse = r.runner.Workers
	for _, lic := range r.nms.Licences {
		if lic.Type == r.runner.Licence {
			lic.InUse += 1
			if err := db.Save(&lic).Error; err != nil {
				return fmt.Errorf("Failed to update licence: %s %s : %v", r.nms.Address, lic.Type, err)
			}
		}
	}

	// Save NMS to db
	if err := db.Save(&r.nms).Error; err != nil {
		return fmt.Errorf("Failed to set nms to active: %v", err)
	}

	return nil
}

func (r *run) start() error {
	logger := r.queue.logger.With(
		zap.String("runner", r.runner.Name),
		zap.String("server", r.server.Hostname),
	)
	// Generate the ruby-script for the runner
	logger.Info("Generating script for runner")
	script, err := ruby.Generate(r.queue.uri, *r.runner)
	if err != nil {
		return fmt.Errorf("failed to generate script for runner: %s - %v", r.runner.Name, err)
	}
	logger.Debug("Script has been generated")

	// Create powershell-connection
	logger.Info("Starting powershell-connection for runner")

	// set options for the connection
	var opts powershell.Options
	opts.Host = r.server.Hostname
	if len(r.server.Username) != 0 {
		logger.Debug("Adding credentials for powershell-session")
		opts.Username = r.server.Username
		opts.Password = r.server.Password
	}

	// create the client
	client, err := powershell.NewClient(r.queue.shell, opts)
	if err != nil {
		return fmt.Errorf("failed to create remote-client for powershell: %v", err)
	}
	r.client = client
	logger.Debug("Powershell-client has been created for runner")

	// Check for case-locks
	if err := removeCaseLocks(client, logger, r.runner.CaseSettings); err != nil {
		client.Close()
		return err
	}

	// Set nuix username as an env-variable
	if err := client.SetEnv("NUIX_USERNAME", r.nms.Username); err != nil {
		client.Close()
		return fmt.Errorf("unable to set NUIX_USERNAME env-variable: %v", err)
	}

	// Set nuix password as an env-variable
	if err := client.SetEnv("NUIX_PASSWORD", r.nms.Password); err != nil {
		client.Close()
		return fmt.Errorf("unable to set NUIX_PASSWORD env-variable: %v", err)
	}

	scriptName := r.runner.Name + ".gen.rb"

	r.queue.logger.Info("Creating runner-script to server",
		zap.String("runner", r.runner.Name),
		zap.String("server", r.server.Hostname),
		zap.String("script", scriptName),
	)

	if err := client.CreateFile(r.server.NuixPath, scriptName, []byte(script)); err != nil {
		client.Close()
		return fmt.Errorf("Failed to create script-file: %v", err)
	}
	defer client.RemoveFile(r.server.NuixPath, scriptName)

	r.queue.logger.Info("STARTING RUNNER",
		zap.String("runner", r.runner.Name),
		zap.String("server", r.server.Hostname),
		zap.String("script", scriptName),
		zap.String("nms", r.nms.Address),
		zap.String("licence", r.runner.Licence),
		zap.Int("workers", int(r.runner.Workers)),
	)

	// format switches for powershell
	var switches []string
	for _, sw := range r.runner.Switches {
		switches = append(switches, fmt.Sprintf("'%s'", sw.Value))
	}

	return client.Run(
		r.server.NuixPath,
		"nuix_console.exe",
		"-Xmx"+r.runner.Xmx,
		fmt.Sprintf("'-Dnuix.registry.servers=%s'", r.nms.Address),
		"-licencesourcetype", "server",
		"-licencesourcelocation", fmt.Sprintf("%s:%d", r.nms.Address, r.nms.Port),
		"-licencetype", r.runner.Licence,
		"-licenceworkers", fmt.Sprintf("%d", r.runner.Workers),
		"-signout",
		strings.Join(switches, " "),
		scriptName,
	)
}

func (r *run) handle(err error) {
	logger := r.queue.logger.With(
		zap.String("runner", r.runner.Name),
		zap.String("server", r.server.Hostname),
		zap.String("nms", r.nms.Address),
		zap.String("licence", r.runner.Licence),
		zap.Int("workers", int(r.runner.Workers)),
	)
	defer r.close()

	// Check for case-locks
	if err := removeCaseLocks(r.client, logger, r.runner.CaseSettings); err != nil {
		logger.Error("Cannot remove case-locks", zap.String("exception", err.Error()))
	}

	logger.Debug("Runner has stopped")
	// handle the error
	if err != nil {
		logger.Error("Runner failed", zap.String("exception", nuixError(err).Error()))
	}
	return
}

func (r *run) close() error {
	if r == nil {
		return errors.New("run is already closed")
	}
	r.queue.logger.Debug("Closing runner", zap.String("runner", r.runner.Name))

	r.client.Close()
	r.client = nil
	r.queue = nil
	r.runner = nil
	r.server = nil
	r.nms = nil
	return nil
}

func getRunners(db *gorm.DB) ([]*api.Runner, error) {
	var runners []*api.Runner
	err := db.
		Preload("Stages.Process.EvidenceStore").
		Preload("Stages.SearchAndTag.Files").
		Preload("Stages.Exclude").
		Preload("Stages.Ocr").
		Preload("Stages.Reload").
		Preload("Stages.Populate.Types").
		Preload("CaseSettings.Case").
		Preload("CaseSettings.CompoundCase").
		Preload("CaseSettings.ReviewCompound").
		Preload("Switches").
		Where("active = ? and status = ?", false, avian.StatusWaiting).
		Find(&runners).Error
	return runners, err
}

func getRunnerByName(db *gorm.DB, name string) (*api.Runner, error) {
	var runner api.Runner
	err := db.Preload("Stages.Process.EvidenceStore").
		Preload("Stages.SearchAndTag.Files").
		Preload("Stages.Exclude").
		Preload("Stages.Ocr").
		Preload("Stages.Reload").
		Preload("Stages.Populate.Types").
		Preload("CaseSettings.Case").
		Preload("CaseSettings.CompoundCase").
		Preload("CaseSettings.ReviewCompound").
		Find(&runner, "name = ?", name).Error
	return &runner, err
}

func activeLicence(db *gorm.DB, address, licencetype string, workers int64) (*api.Nms, error) {
	// Get the requested NMS
	var nms api.Nms
	if err := db.Preload("Licences").First(&nms, "address = ?", address).Error; err != nil {
		return nil, err
	}

	// Check if we have available workers
	if workers > (nms.Workers - nms.InUse) {
		return nil, fmt.Errorf("not enough workers available - requested: %d - available: %d/%d", workers, nms.InUse, nms.Workers)
	}

	// Check if we have a free licence
	for _, lic := range nms.Licences {
		if lic.Type == licencetype {
			if lic.InUse < lic.Amount {
				return &nms, nil
			} else {
				return nil, fmt.Errorf("not enough licences available for %s - %d/%d in use", licencetype, lic.InUse, lic.Amount)
			}
		}
	}
	return nil, fmt.Errorf("did not find licencetype: %s", licencetype)
}

func nuixError(err error) error {
	if !strings.Contains(err.Error(), "Caused by:") {
		return err
	}

	errSlice := strings.Split(err.Error(), "Caused by:")
	if len(errSlice) != 2 {
		return err
	}

	splitted := strings.Split(errSlice[1], "\n")
	newErr := splitted[0]
	return errors.New(newErr)
}

func removeCaseLocks(client *powershell.Client, logger *zap.Logger, caseSettings *api.CaseSettings) error {
	// Check for case-locks
	var caseDirs []string
	caseDirs = append(caseDirs, caseSettings.Case.Directory)
	if caseSettings.CompoundCase != nil {
		caseDirs = append(caseDirs, caseSettings.CompoundCase.Directory)
	}
	if caseSettings.ReviewCompound != nil {
		caseDirs = append(caseDirs, caseSettings.ReviewCompound.Directory)
	}

	logger.Debug("Checking for case.locks in case-directories")
	for _, dir := range caseDirs {
		// if err == nil means the lock exists
		var err error
		caseLock := dir + "/case.lock"
		if powershell.IsUnc(dir) {
			err = client.CheckPathFromHost(caseLock)
		} else {
			err = client.CheckPath(caseLock)
		}
		if err == nil {
			logger.Debug("Found case.lock in case-directory")
			logger.Info("Deleting case.lock in case-directory", zap.String("directory", dir))
			if err := client.RemoveItem(caseLock); err != nil {
				return fmt.Errorf("Failed to remove case.lock from %s : %v", dir, err)
			}
			logger.Debug("Deleted case.lock in case-directory", zap.String("directory", dir))
		}

		caseLockProperties := dir + "/case.lock.properties"
		if powershell.IsUnc(caseLockProperties) {
			err = client.CheckPathFromHost(caseLockProperties)
		} else {
			err = client.CheckPath(caseLockProperties)
		}
		if err == nil {
			logger.Debug("Found case.lock.properties in case-directory")
			logger.Info("Deleting case.lock.properties in case-directory", zap.String("directory", dir))
			if err := client.RemoveItem(caseLockProperties); err != nil {
				return fmt.Errorf("Failed to remove case.lock.properties from %s : %v", dir, err)
			}
			logger.Debug("Deleted case.lock.properties in case-directory", zap.String("directory", dir))
		}
	}
	return nil
}
