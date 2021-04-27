package services

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	api "github.com/avian-digital-forensics/auto-processing/pkg/avian-api"
	"go.uber.org/zap"

	"github.com/jinzhu/gorm"
)

// NmsService holds dependencies
// for the NmsService
type NmsService struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewNmsService creates a new NmsService
func NewNmsService(db *gorm.DB, logger *zap.Logger) NmsService {
	return NmsService{db: db, logger: logger}
}

// Apply applies the nms-servers to the database
func (s NmsService) Apply(ctx context.Context, r api.NmsApplyRequests) (*api.NmsApplyResponse, error) {
	// Start transaction to fall back
	// if we get an error
	s.logger.Debug("Starting db-transaction for NMS-apply")
	tx := s.db.BeginTx(ctx, nil)

	// Create http-client for testing the nms with insecure tls
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}

	// Iterate over the requested nm-servers
	// and append them to the response
	var resp api.NmsApplyResponse
	for _, nms := range r.Nms {
		// Test the http-connection to the NMS
		if _, err := client.Get(fmt.Sprintf("https://%s:%d", nms.Address, nms.Port)); err != nil {
			return nil, fmt.Errorf("Cannot establish connection to NMS with address: %s:%d - %v", nms.Address, nms.Port, err)
		}

		s.logger.Debug("Checking if nms already exists", zap.String("nms", nms.Address))
		// Check if the requested NMS exists (in that case update it)
		var newNms api.Nms
		if err := tx.Preload("Licences").Where("address = ?", nms.Address).First(&newNms).Error; err != nil {
			// return the error if it isn't a "record not found"-error
			if !gorm.IsRecordNotFoundError(err) {
				s.logger.Error("Cannot get nms-server", zap.String("nms", nms.Address), zap.String("exception", err.Error()))
				return nil, err
			}
			s.logger.Debug("NMS already exists - will update", zap.String("nms", nms.Address))
		}

		// Set data to the new Nms-model
		newNms.Address = nms.Address
		newNms.Port = nms.Port
		newNms.Username = nms.Username
		newNms.Password = nms.Password
		newNms.Workers = nms.Workers
		newNms.IsRelay = nms.IsRelay

		// Create hash-map for the existing licences
		s.logger.Debug("Creating hash-map for nms-licences", zap.String("nms", nms.Address))
		hashMap := make(map[string]api.Licence)
		for _, lic := range newNms.Licences {
			hashMap[lic.Type] = lic
		}

		// append the requested licences to the new nms-model
		s.logger.Debug("Iterating through licences to see which to update or create", zap.String("nms", nms.Address))
		for _, lic := range nms.Licences {
			var newLicence api.Licence

			// Check if the licencetype exists in the hashmap and update the amount
			// else create a new licence
			if existing, found := hashMap[lic.Licence.Type]; found {
				newLicence = existing
				s.logger.Debug("Updating licence", zap.String("nms", nms.Address), zap.String("licence", newLicence.Type))
			} else {
				newLicence.Type = lic.Licence.Type
				s.logger.Debug("Adding licence", zap.String("nms", nms.Address), zap.String("licence", newLicence.Type))
			}
			newLicence.Amount = lic.Licence.Amount
			newNms.Licences = append(newNms.Licences, newLicence)
		}

		// Save the new NMS to the DB
		s.logger.Debug("Saving NMS-to db", zap.String("nms", nms.Address))
		if err := tx.Save(&newNms).Error; err != nil {
			tx.Rollback()
			s.logger.Error("Cannot save NMS-to db - rolling back transaction", zap.String("nms", nms.Address), zap.String("exception", err.Error()))
			return nil, fmt.Errorf("failed to apply server %s : %v", newNms.Address, err)
		}

		// Append the new nms to the response
		resp.Nms = append(resp.Nms, newNms)
	}

	s.logger.Debug("Commiting transaction")
	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		s.logger.Error("Commit failed", zap.String("exception", err.Error()))
		return nil, err
	}
	s.logger.Debug("Commit successful")
	return &resp, nil
}

// List lists the NMS-servers from the database
func (s NmsService) List(ctx context.Context, r api.NmsListRequest) (*api.NmsListResponse, error) {
	s.logger.Debug("Getting NMS-list")
	var nms []api.Nms
	if err := s.db.Preload("Licences").Find(&nms).Error; err != nil {
		s.logger.Error("Cannot get NMS-list", zap.String("exception", err.Error()))
		return nil, err
	}
	s.logger.Debug("Got NMS-list", zap.Int("amount", len(nms)))
	return &api.NmsListResponse{Nms: nms}, nil
}

// ListLicences lists licences for the specified NMS-server
func (s NmsService) ListLicences(ctx context.Context, r api.NmsListLicencesRequest) (*api.NmsListLicencesResponse, error) {
	return nil, errors.New("not implemented")
}
