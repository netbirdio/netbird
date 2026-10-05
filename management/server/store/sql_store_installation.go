package store

import (
	"context"

	"gorm.io/gorm/clause"
)

type installation struct {
	ID                  uint `gorm:"primaryKey"`
	InstallationIDValue string
}

func (s *SqlStore) SaveInstallationID(_ context.Context, ID string) error {
	installation := installation{InstallationIDValue: ID}
	installation.ID = uint(s.installationPK)

	return s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&installation).Error
}

func (s *SqlStore) GetInstallationID() string {
	var installation installation

	if result := s.db.Take(&installation, idQueryCondition, s.installationPK); result.Error != nil {
		return ""
	}

	return installation.InstallationIDValue
}
