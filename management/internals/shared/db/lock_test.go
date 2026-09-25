package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/gorm/clause"
)

func TestWithLock(t *testing.T) {
	conn := openTestConn(t)
	base := conn.DB(nil)

	assert.Same(t, base, WithLock(base, LockingStrengthNone))

	locked, ok := WithLock(base, LockingStrengthUpdate).Statement.Clauses["FOR"]
	assert.True(t, ok)
	assert.Equal(t, clause.Locking{Strength: "UPDATE"}, locked.Expression)
}
