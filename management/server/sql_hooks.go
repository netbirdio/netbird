package server

import (
	"time"

	"gorm.io/gorm"
)

func GetDefaultTimezone() time.Time {
	return time.Date(1, 1, 1, 1, 1, 1, 1, time.Local)
}

func (u *SetupKey) BeforeSave(tx *gorm.DB) (err error) {

	if u.CreatedAt.IsZero() {
		u.CreatedAt = GetDefaultTimezone()
	}

	if u.ExpiresAt.IsZero() {
		u.ExpiresAt = GetDefaultTimezone()
	}

	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = GetDefaultTimezone()
	}

	if u.LastUsed.IsZero() {
		u.LastUsed = GetDefaultTimezone()
	}

	return nil
}
