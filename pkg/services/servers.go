package services

import (
	"context"
	"fmt"

	api "github.com/avian-digital-forensics/auto-processing/pkg/avian-api"
	"github.com/avian-digital-forensics/auto-processing/pkg/pwsh"
	"go.uber.org/zap"

	"github.com/jinzhu/gorm"
)

type ServerService struct {
	db     *gorm.DB
	shell  pwsh.Powershell
	logger *zap.Logger
}

func NewServerService(db *gorm.DB, shell pwsh.Powershell, logger *zap.Logger) ServerService {
	return ServerService{db: db, shell: shell, logger: logger}
}

func (s ServerService) Apply(ctx context.Context, r api.ServerApplyRequest) (*api.ServerApplyResponse, error) {
	logger := s.logger.With(
		zap.String("server", r.Hostname),
		zap.String("os", r.OperatingSystem),
		zap.String("nuix_path", r.NuixPath),
		zap.String("service_account", r.Username),
	)

	if r.OperatingSystem != "linux" && r.OperatingSystem != "windows" {
		logger.Error("specify operating system - 'linux' or 'windows'", zap.String("exception", "invalid operating system"))
		return nil, fmt.Errorf("specify operating_system for %s - 'linux' or 'windows'", r.Hostname)
	}

	// Check if the requested server exists (in that case update it)
	logger.Debug("Checking if server already exists")
	var newSrv api.Server
	if err := s.db.Where("hostname = ?", r.Hostname).First(&newSrv).Error; err != nil {
		// return the error if it isn't a "record not found"-error
		if !gorm.IsRecordNotFoundError(err) {
			logger.Error("Cannot get the server", zap.String("exception", err.Error()))
			return nil, err
		}
		logger.Debug("Server already exist - will update instead of create new")
	}

	// Test connection
	logger.Debug("Checking if the server should be tested or not")
	if newSrv.ID == 0 {
		logger.Debug("Testing the server")

		// create the client
		logger.Info("Creating powershell-session for the testing server")
		session, err := s.shell.NewSession(r.Hostname, r.Username, r.Password)
		if err != nil {
			logger.Error("Failed to create remote-client for powershell", zap.String("exception", err.Error()))
			return nil, fmt.Errorf("failed to create remote-client for powershell: %v", err)
		}
		// close the client on exit
		defer session.Close()

		logger.Debug("Enabling CredSSP")
		if err := session.EnableCredSSP(); err != nil {
			logger.Error("Failed to enable CredSSP", zap.String("exception", err.Error()))
			return nil, fmt.Errorf("failed to enable credssp: %v", err)
		}
	}

	session, err := s.shell.NewSessionCredSSP(r.Hostname, r.Username, r.Password)
	if err != nil {
		logger.Error("Failed to create remote-client for powershell with CredSSP", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("failed to create remote-client for powershell: %v", err)
	}
	defer session.Close()

	if newSrv.NuixPath != r.NuixPath {
		if err := session.CheckPath(r.NuixPath); err != nil {
			logger.Error("Failed to test NuixPath for server", zap.String("exception", err.Error()))
			return nil, fmt.Errorf("failed to test nuix-path for server: %v", err)
		}
		logger.Debug("Nuix-path is ok for server")
	}

	if newSrv.AvianScripts != r.AvianScripts {
		if err := session.CheckPath(r.AvianScripts); err != nil {
			logger.Error("Failed to test AvianScripts-path for server", zap.String("exception", err.Error()))
			return nil, fmt.Errorf("failed to test nuix-path for server: %v", err)
		}

		logger.Debug("Avian-scripts path is ok for server")
	}

	// Set data to the new Server-model
	newSrv.Hostname = r.Hostname
	newSrv.Port = r.Port
	newSrv.Username = r.Username
	newSrv.Password = r.Password
	newSrv.OperatingSystem = r.OperatingSystem
	newSrv.NuixPath = r.NuixPath
	newSrv.AvianScripts = r.AvianScripts

	// Save the new NMS to the DB
	logger.Info("Saving server to the DB")
	if err := s.db.Save(&newSrv).Error; err != nil {
		logger.Error("Cannot save server to DB", zap.String("exception", err.Error()))
		return nil, fmt.Errorf("failed to apply server %s : %v", newSrv.Hostname, err)
	}

	logger.Debug("Server has been saved to the DB")
	return &api.ServerApplyResponse{}, nil
}

func (s ServerService) List(ctx context.Context, r api.ServerListRequest) (*api.ServerListResponse, error) {
	s.logger.Debug("Getting Servers-list")
	var servers []api.Server
	if err := s.db.Find(&servers).Error; err != nil {
		s.logger.Error("Cannot get Servers-list", zap.String("exception", err.Error()))
		return nil, err
	}
	s.logger.Debug("Got Servers-list", zap.Int("amount", len(servers)))
	return &api.ServerListResponse{Servers: servers}, nil
}
