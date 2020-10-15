package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	api "github.com/avian-digital-forensics/auto-processing/pkg/avian-api"
	avian "github.com/avian-digital-forensics/auto-processing/pkg/avian-client"
	"github.com/avian-digital-forensics/auto-processing/pkg/logging"
	"github.com/avian-digital-forensics/auto-processing/pkg/pwsh"

	"github.com/jinzhu/gorm"
	"go.uber.org/zap"
)

type RunnerService struct {
	DB         *gorm.DB
	shell      pwsh.Powershell
	logger     *zap.Logger
	logHandler logging.Service
}

func NewRunnerService(db *gorm.DB, shell pwsh.Powershell, logger *zap.Logger, logHandler logging.Service) RunnerService {
	return RunnerService{
		DB:         db,
		shell:      shell,
		logger:     logger,
		logHandler: logHandler,
	}
}

// Apply the runner to backend
func (s RunnerService) Apply(ctx context.Context, r api.RunnerApplyRequest) (*api.RunnerApplyResponse, error) {
	s.logger.Debug("Runner apply-request")

	logger := s.logger.With(
		zap.String("runner", r.Name),
		zap.String("hostname", r.Hostname),
		zap.String("nms", r.Nms),
		zap.String("licence", r.Licence),
		zap.Int("workers", int(r.Workers)),
		zap.String("xmx", r.Xmx),
	)

	logger.Debug("Creating runner")
	// Create the requested runner

	// add the switches
	var switches []*api.NuixSwitch
	for _, nuixSwitch := range r.Switches {
		switches = append(switches, &api.NuixSwitch{Value: nuixSwitch})
	}

	runner := api.Runner{
		Name:         r.Name,
		Hostname:     r.Hostname,
		Nms:          r.Nms,
		Licence:      r.Licence,
		Xmx:          r.Xmx,
		Workers:      r.Workers,
		CaseSettings: r.CaseSettings,
		Stages:       r.Stages,
		Switches:     switches,
	}

	// Validate the runner
	logger.Info("Validating runner")
	if err := runner.Validate(); err != nil {
		logger.Error("Validation failed for runner", zap.String("exception", err.Error()))
		return nil, err
	}
	logger.Debug("Validation OK")

	logger.Info("Looking if runner already exists")
	var fromDB api.Runner
	fromDB.Name = r.Name
	if err := getPreloadedRunner(s.DB, &fromDB); err != nil {
		if !gorm.IsRecordNotFoundError(err) {
			return nil, fmt.Errorf("unknown error: %v", err)
		}
	}

	// Create transaction for deleting and creating stages
	tx := s.DB.Begin()

	if fromDB.ID != 0 {
		if !r.Update {
			logger.Error("Create a new runner by a unique name or update existing", zap.String("exception", "runner already exists"))
			tx.Rollback()
			return nil, fmt.Errorf("runner: %s already exist, create a new runner by a unique name", runner.Name)
		}

		if fromDB.Active {
			logger.Error("Runner is active, cannot update an active runner")
			tx.Rollback()
			return nil, errors.New("cannot update active runner")
		}

		runner.ID = fromDB.ID
		runner.CaseSettings.ID = fromDB.CaseSettings.ID
		runner.CaseSettings.Case.ID = fromDB.CaseSettings.ID
		runner.CaseSettings.CompoundCase.ID = fromDB.CaseSettings.CompoundCase.ID
		runner.CaseSettings.ReviewCompound.ID = fromDB.CaseSettings.ReviewCompound.ID

		var stageMap = make(map[uint]api.Stage)
		for index, stage := range runner.Stages {
			stageMap[uint(index)] = *stage
		}

		var newStages []*api.Stage
		for _, stage := range fromDB.Stages {
			newStage, ok := stageMap[stage.Index]
			if ok && avian.StageState(stage) == avian.StatusFinished && avian.Name(&newStage) == avian.Name(stage) {
				continue
			}

			if stage.Process != nil {
				for _, evidence := range stage.Process.EvidenceStore {
					if err := tx.Delete(&evidence).Error; err != nil {
						tx.Rollback()
						logger.Error("Failed to delete evidence", zap.String("exception", err.Error()))
						return nil, fmt.Errorf("failed to delete evidence: %v", err)
					}
				}
			}

			if err := tx.Delete(&stage).Error; err != nil {
				tx.Rollback()
				logger.Error("Failed to delete stage", zap.String("stage", avian.Name(stage)), zap.String("exception", err.Error()))
				return nil, fmt.Errorf("failed to delete stage: %s - %v", avian.Name(stage), err)
			}

			newStages = append(newStages, &newStage)
		}
		runner.Stages = newStages
	}

	// Check if the requested server exists
	var server api.Server
	logger.Info("Looking if server exists")
	if s.DB.First(&server, "hostname = ?", runner.Hostname).RecordNotFound() {
		logger.Error("Requested server for runner does not exist", zap.String("exception", "server not found"))
		tx.Rollback()
		return nil, fmt.Errorf("server: %s doesn't exist in the backend, list existing servers by command: 'avian servers list'", runner.Hostname)
	}

	// Check if the requested nms exists
	logger.Info("Looking if NMS exist")
	if s.DB.First(&api.Nms{}, "address = ?", runner.Nms).RecordNotFound() {
		logger.Error("Requested NMS for runner does not exist", zap.String("exception", "nms not found"))
		tx.Rollback()
		return nil, fmt.Errorf("nms: %s doesn't exist in the backend, list existing nm-servers by command: 'avian nms list'", runner.Nms)
	}

	// Create powershell-connection to test the server
	logger.Info("Creating powershell-session for runner")
	session, err := s.shell.NewSessionCredSSP(server.Hostname, server.Username, server.Password)
	if err != nil {
		logger.Error("Failed to create remote-client for powershell", zap.String("exception", err.Error()))
		tx.Rollback()
		return nil, fmt.Errorf("failed to create remote-client for powershell: %v", err)
	}

	// close the client on exit
	defer session.Close()

	// check that all the paths for the runner exists in the server
	logger.Info("Validating paths for runner")
	for _, path := range runner.Paths() {
		if err := session.CheckPath(path); err != nil {
			logger.Error("Failed to validate path", zap.String("path", path), zap.String("exception", err.Error()))
			tx.Rollback()
			return nil, fmt.Errorf("path: %s - err : %v", path, err)
		}
	}

	// Add the runner to the db
	logger.Info("Saving runner to DB")
	runner.Status = avian.StatusWaiting
	if err := tx.Save(&runner).Error; err != nil {
		tx.Rollback()
		logger.Error("Cannot to save runner to DB", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("failed to create runner: %v", err)
	}

	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		logger.Error("Cannot commit transaction to DB", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("failed to create runner: %v", err)
	}

	logger.Info("Runner has been created")
	return &api.RunnerApplyResponse{Runner: runner}, nil
}

func (s RunnerService) List(ctx context.Context, r api.RunnerListRequest) (*api.RunnerListResponse, error) {
	s.logger.Debug("Getting runners-list")
	var runners []api.Runner
	err := s.DB.Preload("Stages.Process").
		Preload("Stages.SearchAndTag").
		Preload("Stages.Exclude").
		Preload("Stages.Ocr").
		Preload("Stages.Reload").
		Preload("Stages.Populate").
		Find(&runners).Error
	if err != nil {
		s.logger.Error("Cannot get runners-list", zap.String("exception", err.Error()))
		return nil, err
	}
	s.logger.Debug("Got Runners-list", zap.Int("amount", len(runners)))
	return &api.RunnerListResponse{Runners: runners}, nil
}

func (s RunnerService) Get(ctx context.Context, r api.RunnerGetRequest) (*api.RunnerGetResponse, error) {
	s.logger.Debug("Getting runner", zap.String("runner", r.Name))
	var runner api.Runner
	err := s.DB.Preload("Stages.Process").
		Preload("Stages.SearchAndTag").
		Preload("Stages.Exclude").
		Preload("Stages.Ocr").
		Preload("Stages.Reload").
		Preload("Stages.Populate").
		Preload("CaseSettings.Case").
		Preload("CaseSettings.CompoundCase").
		Preload("CaseSettings.ReviewCompound").
		First(&runner, "name = ?", r.Name).Error
	if err != nil {
		s.logger.Error("Cannot get runner", zap.String("runner", r.Name), zap.String("exception", err.Error()))
		return nil, err
	}
	s.logger.Debug("Returning runner", zap.String("runner", r.Name))
	return &api.RunnerGetResponse{Runner: runner}, nil
}

func (s RunnerService) Delete(ctx context.Context, r api.RunnerDeleteRequest) (*api.RunnerDeleteResponse, error) {
	s.logger.Debug("Getting runner to delete", zap.String("runner", r.Name))
	if r.DeleteAllCases {
		// Delete all cases associated with the runner
	} else if r.DeleteCase {
		// Delete the single-case for the runner
	}

	// start transaction for the delete
	tx := s.DB.Begin()

	var runner api.Runner
	err := tx.Preload("Switches").
		Preload("Stages.Process").
		Preload("Stages.SearchAndTag").
		Preload("Stages.Exclude").
		Preload("Stages.Ocr").
		Preload("Stages.Reload").
		Preload("Stages.Populate").
		Preload("CaseSettings.Case").
		Preload("CaseSettings.CompoundCase").
		Preload("CaseSettings.ReviewCompound").
		First(&runner, "name = ? OR id = ?", r.Name, r.Name).Error
	if err != nil {
		tx.Rollback()
		s.logger.Error("Cannot get runner", zap.String("runner", r.Name), zap.String("exception", err.Error()))
		return nil, err
	}

	// check if the runner is active
	// unless the delete is forced
	if runner.Active {
		if !r.Force {
			tx.Rollback()
			s.logger.Error("Cannot delete active runner", zap.String("runner", r.Name))
			return nil, fmt.Errorf("Cannot delete active runner - use force argument")
		}

		// set the runners server to inactive
		if err := tx.Model(&api.Server{}).Where("hostname = ?", runner.Hostname).Update("active", false).Error; err != nil {
			tx.Rollback()
			s.logger.Error("Cannot set server to inactive",
				zap.String("runner", r.Name),
				zap.String("server", runner.Hostname),
				zap.String("exception", err.Error()),
			)
			return nil, fmt.Errorf("Cannot set the active server to inactive: %v", err)
		}
	}

	s.logger.Debug("Deleting runner", zap.String("runner", r.Name))
	if err := tx.Delete(&runner).Error; err != nil {
		tx.Rollback()
		s.logger.Error("Cannot delete runner", zap.String("runner", r.Name), zap.String("exception", err.Error()))
		return nil, err
	}

	if err := tx.Model(&runner).Association("Stages").Delete(runner.Stages).Error; err != nil {
		tx.Rollback()
		s.logger.Error("Cannot delete runner", zap.String("runner", r.Name), zap.String("exception", err.Error()))
		return nil, err
	}

	if err := tx.Model(&runner).Association("Switches").Delete(runner.Switches).Error; err != nil {
		tx.Rollback()
		s.logger.Error("Cannot delete runner", zap.String("runner", r.Name), zap.String("exception", err.Error()))
		return nil, err
	}

	if err := tx.Model(&runner).Association("CaseSettings").Delete(runner.CaseSettings).Error; err != nil {
		tx.Rollback()
		s.logger.Error("Cannot delete runner", zap.String("runner", r.Name), zap.String("exception", err.Error()))
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		s.logger.Error("Cannot delete runner, failed to commit transaction", zap.String("runner", r.Name), zap.String("exception", err.Error()))
		return nil, err
	}

	return &api.RunnerDeleteResponse{}, nil
}

func (s RunnerService) Start(ctx context.Context, r api.RunnerStartRequest) (*api.RunnerStartResponse, error) {
	logger := s.logger.With(zap.String("runner", r.Runner), zap.Int("runner_id", int(r.ID)))
	logger.Info("STARTING RUNNER")
	var runner api.Runner
	if err := s.DB.First(&runner, r.ID).Error; err != nil {
		logger.Error("Cannot get runner", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("cannot get runner: %v", err)
	}
	now := time.Now()
	runner.Status = avian.StatusRunning
	runner.HealthyAt = &now
	if err := s.DB.Save(&runner).Error; err != nil {
		logger.Error("Cannot save the started runner", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("cannot save runner: %v", err)
	}

	return &api.RunnerStartResponse{}, nil
}

func (s RunnerService) Failed(ctx context.Context, r api.RunnerFailedRequest) (*api.RunnerFailedResponse, error) {
	logger := s.logger.With(zap.String("runner", r.Runner), zap.Int("runner_id", int(r.ID)))
	logger.Info("FAILED RUNNER")
	var runner api.Runner
	if err := s.DB.First(&runner, r.ID).Error; err != nil {
		logger.Error("Cannot get runner", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("cannot get runner: %v", err)
	}
	runner.Status = avian.StatusFailed
	runner.Active = false
	if err := s.DB.Save(&runner).Error; err != nil {
		logger.Error("Cannot save the failed runner", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("cannot save runner: %v", err)
	}

	// Set servers activity
	if err := s.SetServerActivity(runner, false); err != nil {
		return nil, fmt.Errorf("Failed to set servers activity: %v", err)
	}

	// update nms information
	if err := s.ResetNms(runner); err != nil {
		return nil, fmt.Errorf("Failed to set servers activity: %v", err)
	}

	if err := s.RemoveScript(runner); err != nil {
		return nil, err
	}

	return &api.RunnerFailedResponse{}, nil
}

func (s RunnerService) Finish(ctx context.Context, r api.RunnerFinishRequest) (*api.RunnerFinishResponse, error) {
	logger := s.logger.With(zap.String("runner", r.Runner), zap.Int("runner_id", int(r.ID)))
	logger.Info("FINISHED RUNNER")

	var runner api.Runner
	if err := s.DB.First(&runner, r.ID).Error; err != nil {
		logger.Error("Cannot get runner", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("cannot get runner: %v", err)
	}
	runner.Status = avian.StatusFinished
	runner.Active = false
	if err := s.DB.Save(&runner).Error; err != nil {
		logger.Error("Cannot save the failed runner", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("cannot save runner: %v", err)
	}

	// Set servers activity
	if err := s.SetServerActivity(runner, false); err != nil {
		return nil, fmt.Errorf("Failed to set servers activity: %v", err)
	}

	// update nms information
	if err := s.ResetNms(runner); err != nil {
		return nil, fmt.Errorf("Failed to set servers activity: %v", err)
	}

	if err := s.RemoveScript(runner); err != nil {
		return nil, err
	}

	return &api.RunnerFinishResponse{}, nil
}

func (s RunnerService) Heartbeat(ctx context.Context, r api.RunnerStartRequest) (*api.RunnerStartResponse, error) {
	logger := s.logger.With(zap.String("runner", r.Runner), zap.Int("runner_id", int(r.ID)))
	logger.Debug("Retrieved heartbeat from runner")
	if err := s.DB.Model(&api.Runner{}).Where("id = ?", r.ID).Update("healthy_at", time.Now()).Error; err != nil {
		logger.Error("Failed to update healthy_at", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("Failed to update healthy_at: %v", err)
	}
	return &api.RunnerStartResponse{}, nil
}

func (s RunnerService) StartStage(ctx context.Context, r api.StageRequest) (*api.StageResponse, error) {
	logger := s.logger.With(zap.String("runner", r.Runner), zap.Int("stage_id", int(r.StageID)))
	logger.Debug("StartStage request")
	var stage api.Stage
	if err := s.DB.Preload("Process").
		Preload("SearchAndTag").
		Preload("Exclude").
		Preload("Reload").
		Preload("Populate").
		Preload("Ocr").
		First(&stage, r.StageID).Error; err != nil {
		logger.Error("Cannot get the requested stage", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("did not get requested stage : %v", err)
	}

	logger.Debug("Set stage-status to running", zap.Int("stage_id", int(r.StageID)))
	avian.SetStatusRunning(&stage)
	if err := s.DB.Save(&stage).Error; err != nil {
		logger.Error("Cannot set stage-status to running", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("failed to update stage to running: %v", err)
	}

	logger.Info("STARTING STAGE", zap.String("stage", avian.Name(&stage)))
	return &api.StageResponse{Stage: stage}, nil
}

func (s RunnerService) FailedStage(ctx context.Context, r api.StageRequest) (*api.StageResponse, error) {
	logger := s.logger.With(zap.String("runner", r.Runner), zap.Int("stage_id", int(r.StageID)))
	logger.Debug("FailedStage request")
	var stage api.Stage
	if err := s.DB.Preload("Process").
		Preload("SearchAndTag").
		Preload("Exclude").
		Preload("Reload").
		Preload("Populate").
		Preload("Ocr").
		First(&stage, r.StageID).Error; err != nil {
		logger.Error("Cannot get the requested stage", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("did not get requested stage : %v", err)
	}

	logger.Debug("Set stage-status to failed", zap.Int("stage_id", int(r.StageID)))
	avian.SetStatusFailed(&stage)
	if err := s.DB.Save(&stage).Error; err != nil {
		logger.Error("Cannot set stage-status to failed", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("cannot to update stage to failed: %v", err)
	}

	logger.Info("FAILED STAGE", zap.String("stage", avian.Name(&stage)))
	return &api.StageResponse{Stage: stage}, nil
}

func (s RunnerService) FinishStage(ctx context.Context, r api.StageRequest) (*api.StageResponse, error) {
	logger := s.logger.With(zap.String("runner", r.Runner), zap.Int("stage_id", int(r.StageID)))
	logger.Debug("FinishStage request")
	var stage api.Stage
	if err := s.DB.Preload("Process").
		Preload("SearchAndTag").
		Preload("Exclude").
		Preload("Reload").
		Preload("Populate").
		Preload("Ocr").
		First(&stage, r.StageID).Error; err != nil {
		logger.Error("Cannot get the requested stage", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("did not get requested stage : %v", err)
	}

	logger.Debug("Set stage-status to finished", zap.Int("stage_id", int(r.StageID)))
	avian.SetStatusFinished(&stage)
	if err := s.DB.Save(&stage).Error; err != nil {
		logger.Error("Cannot set stage-status to finished", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("failed to update stage to running: %v", err)
	}

	logger.Info("FINISHED STAGE", zap.String("stage", avian.Name(&stage)))
	return &api.StageResponse{Stage: stage}, nil
}

// LogItem logs an item that has been processed
func (s RunnerService) LogItem(ctx context.Context, r api.LogItemRequest) (*api.LogResponse, error) {
	logger, err := s.logHandler.Get(r.Runner + "-item.log")
	if err != nil {
		return nil, err
	}

	logger = logger.With(
		zap.String("runner", r.Runner),
		zap.String("stage", r.Stage),
		zap.Int("stage_id", r.StageID),
		zap.Int("count", r.Count),
	)

	if len(r.ProcessStage) > 0 {
		logger = logger.With(zap.String("process_stage", r.ProcessStage))
	}
	if len(r.MimeType) > 0 {
		logger = logger.With(zap.String("mime_type", r.MimeType))
	}
	if len(r.GUID) > 0 {
		logger = logger.With(zap.String("guid", r.GUID))
	}

	logger.Debug(r.Message)
	return &api.LogResponse{}, nil
}

func (s RunnerService) LogDebug(ctx context.Context, r api.LogRequest) (*api.LogResponse, error) {
	logger, err := s.logHandler.Get(r.Runner + "-runner.log")
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	logger = logger.With(zap.String("runner", r.Runner))
	if len(r.Stage) > 0 {
		logger = logger.With(zap.Int("stage_id", r.StageID), zap.String("stage", r.Stage))
	}

	logger.Debug(r.Message)
	return &api.LogResponse{}, nil
}

func (s RunnerService) LogInfo(ctx context.Context, r api.LogRequest) (*api.LogResponse, error) {
	logger, err := s.logHandler.Get(r.Runner + "-runner.log")
	if err != nil {
		return nil, err
	}

	logger.With(zap.String("runner", r.Runner))
	if len(r.Stage) > 0 {
		logger = logger.With(zap.Int("stage_id", r.StageID), zap.String("stage", r.Stage))
	}

	logger.Info(r.Message)
	return &api.LogResponse{}, nil
}

func (s RunnerService) LogError(ctx context.Context, r api.LogRequest) (*api.LogResponse, error) {
	logger, err := s.logHandler.Get(r.Runner + "-runner.log")
	if err != nil {
		return nil, err
	}

	logger = logger.With(zap.String("runner", r.Runner))
	if len(r.Stage) > 0 {
		logger = logger.With(zap.Int("stage_id", r.StageID), zap.String("stage", r.Stage))
	}
	if len(r.Exception) > 0 {
		logger = logger.With(zap.String("exception", r.Exception))
	}

	logger.Error(r.Message)
	return &api.LogResponse{}, nil
}

func (s RunnerService) SetServerActivity(runner api.Runner, active bool) error {
	if err := s.DB.Model(&api.Server{}).Where("hostname = ?", runner.Hostname).Update("active", active).Error; err != nil {
		s.logger.Error("Cannot set servers activity",
			zap.String("runner", runner.Name),
			zap.String("server", runner.Hostname),
			zap.String("exception", err.Error()),
		)
		return err
	}
	return nil
}

func (s RunnerService) ResetNms(runner api.Runner) error {
	// Get the latest data for the nms-server
	var nms api.Nms
	if err := s.DB.Preload("Licences").First(&nms, "address = ?", runner.Nms).Error; err != nil {
		s.logger.Error("Cannot get NMS from DB",
			zap.String("runner", runner.Name),
			zap.String("nms", runner.Nms),
			zap.String("exception", err.Error()),
		)
		return err
	}

	// Reset the licences for the nms
	nms.InUse = nms.InUse - runner.Workers
	for _, lic := range nms.Licences {
		if lic.Type == runner.Licence {
			lic.InUse = lic.InUse - 1
			if err := s.DB.Save(&lic).Error; err != nil {
				s.logger.Error("Cannot update licence-information to DB",
					zap.String("runner", runner.Name),
					zap.String("nms", runner.Nms),
					zap.String("licence", lic.Type),
					zap.String("exception", err.Error()),
				)
				return err
			}
		}
	}

	// update the nms to the db
	if err := s.DB.Save(&nms).Error; err != nil {
		s.logger.Error("Cannot update nms-information to DB",
			zap.String("runner", runner.Name),
			zap.String("nms", runner.Nms),
			zap.String("licence", runner.Licence),
			zap.String("exception", err.Error()),
		)
		return err
	}
	return nil
}

func getPreloadedRunner(db *gorm.DB, runner *api.Runner) error {
	return db.Preload("Stages.Process.EvidenceStore").
		Preload("Stages.SearchAndTag.Files").
		Preload("Stages.Exclude").
		Preload("Stages.Ocr").
		Preload("Stages.Reload").
		Preload("Stages.Populate.Types").
		Preload("CaseSettings.Case").
		Preload("CaseSettings.CompoundCase").
		Preload("CaseSettings.ReviewCompound").
		Preload("Switches").
		First(&runner, "name = ?", runner.Name).Error
}

func (s RunnerService) RemoveScript(runner api.Runner) error {
	logger := s.logger.With(zap.String("runner", runner.Name))
	var server api.Server
	if err := s.DB.First(&server, "hostname = ?", runner.Hostname).Error; err != nil {
		logger.Error("Failed to retrive server from db", zap.String("server", runner.Hostname), zap.String("exception", err.Error()))
		return fmt.Errorf("Failed to retrive server from db: %s - %v", runner.Hostname, err.Error())
	}

	logger.Info("Creating powershell-session for runner")
	session, err := s.shell.NewSessionCredSSP(server.Hostname, server.Username, server.Password)
	if err != nil {
		logger.Error("Failed to create remote-client for powershell", zap.String("exception", err.Error()))
		return fmt.Errorf("failed to create remote-client for powershell: %v", err)
	}

	// close the client on exit
	defer session.Close()

	var scriptName = fmt.Sprintf("%s\\%s.gen.rb", server.NuixPath, runner.Name)
	if err := session.RemoveItem(scriptName); err != nil {
		logger.Error("Failed to remove script-file in ps-session",
			zap.String("server", runner.Hostname),
			zap.String("nuix_path", server.NuixPath),
			zap.String("exception", err.Error()),
		)
		return fmt.Errorf("Failed to set nuix-path in ps-session: %s - %v", runner.Hostname, err.Error())
	}
	return nil
}
