package heartbeat

import (
	"time"

	api "github.com/avian-digital-forensics/auto-processing/pkg/avian-api"
	"github.com/avian-digital-forensics/auto-processing/pkg/avian-client"
	"github.com/avian-digital-forensics/auto-processing/pkg/services"
	"github.com/jinzhu/gorm"
	"go.uber.org/zap"
)

// Service holds dependencies
// for the heartbeat
type Service struct {
	runnersvc services.RunnerService
	pause     time.Duration
	db        *gorm.DB
	logger    *zap.Logger
}

// New creates a new heartbeat.Service
func New(r services.RunnerService, logger *zap.Logger) Service {
	return Service{r, 2 * time.Minute, r.DB, logger}
}

// Beat will check if there is any unhealthy runners
// and set those to timed out
func (s Service) Beat() {
	for {
		// get the unhealthy runners
		var runners []api.Runner
		var lastCheck = time.Now().Add(-s.pause)
		var query = s.db.Where("active = ? AND healthy_at < ?", true, lastCheck)
		if err := query.Find(&runners).Error; err != nil {
			s.logger.Error("Failed to fetch runners", zap.String("exception", err.Error()))
		}
		s.logger.Info("Got unhealthy runners from db", zap.Int("amount", len(runners)))

		// iterate over the unhealthy runnres
		for _, runner := range runners {
			// set status to timeout and active to false
			runner.Status = avian.StatusTimeout
			runner.Active = false
			if err := s.db.Save(&runner).Error; err != nil {
				s.logger.Error("Cannot save the failed runner", zap.String("exception", err.Error()))
			}

			// Set servers activity
			if err := s.runnersvc.SetServerActivity(runner, false); err != nil {
				s.logger.Error("Cannot save the failed runner", zap.String("exception", err.Error()))
			}

			// update nms information
			if err := s.runnersvc.ResetNms(runner); err != nil {
				s.logger.Error("Cannot save the failed runner", zap.String("exception", err.Error()))
			}

			// remove the script from the remote machine
			if err := s.runnersvc.RemoveScript(runner); err != nil {
				s.logger.Error("Cannot remove script for runner", zap.String("exception", err.Error()))
			}
		}

		time.Sleep(s.pause)
	}
}
