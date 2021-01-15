package datastore

import (
	"time"

	"github.com/jinzhu/gorm"
)

// Base model for the database-models
type Base struct {
	ID    uint   `json:"id" gorm:"AUTO_INCREMENT"`
	CTime int64  `json:"cTime"`
	MTime int64  `json:"mTime"`
	DTime *int64 `sql:"index" json:"dTime"`
}

// BeforeCreate sets CTime to current unix-timestamp
func (b *Base) BeforeCreate(scope *gorm.Scope) error {
	scope.SetColumn("CTime", time.Now().Unix())
	return nil
}

// BeforeSave sets CTime and MTime to current unix-timestamp
func (b *Base) BeforeSave(scope *gorm.Scope) (err error) {
	scope.SetColumn("CTime", time.Now().Unix())
	scope.SetColumn("MTime", time.Now().Unix())
	return nil
}

// BeforeUpdate sets MTime to current unix-timestamp
func (b *Base) BeforeUpdate(scope *gorm.Scope) (err error) {
	scope.SetColumn("MTime", time.Now().Unix())
	return nil
}

// BeforeDelete sets DTime to current unix-timestamp
func (b *Base) BeforeDelete(scope *gorm.Scope) (err error) {
	scope.SetColumn("DTime", time.Now().Unix())
	return nil
}
