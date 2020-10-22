package tables

import (
	"fmt"

	api "github.com/avian-digital-forensics/auto-processing/pkg/avian-api"
	"github.com/jinzhu/gorm"
)

// Migrate the db-tables
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&api.Nms{},
		&api.Licence{},
		&api.Server{},
		&api.Runner{},
		&api.NuixSwitch{},
		&api.CaseSettings{},
		&api.Case{},
		&api.Evidence{},
		&api.Stage{},
		&api.Process{},
		&api.SearchAndTag{},
		&api.Exclude{},
		&api.Populate{},
		&api.Reload{},
		&api.Ocr{},
		&api.File{},
		&api.Type{},
		&api.InApp{},
	).Error
}

// Index the tables
func Index(db *gorm.DB) error {
	// add index to nms-address
	if err := db.Model(&api.Nms{}).AddIndex("idx_nms_address", "address").Error; err != nil {
		return fmt.Errorf("unable to add index to nms-address")
	}

	// add index to server-hostname
	if err := db.Model(&api.Server{}).AddIndex("idx_server_hostname", "hostname").Error; err != nil {
		return fmt.Errorf("unable to add index to server-hostname")
	}

	// add index to runner-name
	if err := db.Model(&api.Runner{}).AddIndex("idx_runner_name", "name").Error; err != nil {
		return fmt.Errorf("unable to add index to server-hostname")
	}
	return nil
}
