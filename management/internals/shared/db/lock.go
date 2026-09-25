package db

import (
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// LockingStrength is the row lock a query holds until its transaction ends.
type LockingStrength string

const (
	LockingStrengthUpdate      LockingStrength = "UPDATE"
	LockingStrengthShare       LockingStrength = "SHARE"
	LockingStrengthNoKeyUpdate LockingStrength = "NO KEY UPDATE"
	LockingStrengthKeyShare    LockingStrength = "KEY SHARE"
	LockingStrengthNone        LockingStrength = "NONE"
)

// WithLock adds the row lock clause to query unless strength is LockingStrengthNone.
func WithLock(query *gorm.DB, strength LockingStrength) *gorm.DB {
	if strength == LockingStrengthNone {
		return query
	}
	return query.Clauses(clause.Locking{Strength: string(strength)})
}
