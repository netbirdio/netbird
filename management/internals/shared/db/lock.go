package db

// LockingStrength is the row lock a query holds until its transaction ends.
type LockingStrength string

const (
	LockingStrengthUpdate      LockingStrength = "UPDATE"
	LockingStrengthShare       LockingStrength = "SHARE"
	LockingStrengthNoKeyUpdate LockingStrength = "NO KEY UPDATE"
	LockingStrengthKeyShare    LockingStrength = "KEY SHARE"
	LockingStrengthNone        LockingStrength = "NONE"
)
