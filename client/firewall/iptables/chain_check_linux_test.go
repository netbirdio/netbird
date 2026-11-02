//go:build !android

package iptables

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A failed chain check only means "no such chain" when the table itself is not there. A
// failure with the table present, such as a held xtables lock or missing permission, has to
// reach the caller, or a cleanup would report success without having looked.
func TestChainCheckResult(t *testing.T) {
	checkErr := errors.New("check failed")
	tableMissing := func() error { return errors.New("no such table") }
	tablePresent := func() error { return nil }

	ok, err := chainCheckResult(true, nil, true, tablePresent)
	assert.True(t, ok, "a found chain is reported")
	assert.NoError(t, err)

	ok, err = chainCheckResult(false, checkErr, true, tableMissing)
	assert.False(t, ok, "a missing table holds no chains")
	assert.NoError(t, err, "a missing table is not an error")

	ok, err = chainCheckResult(false, checkErr, true, tablePresent)
	assert.False(t, ok)
	assert.ErrorIs(t, err, checkErr, "a failure with the table present must be returned")

	ok, err = chainCheckResult(false, checkErr, false, tableMissing)
	assert.False(t, ok)
	assert.ErrorIs(t, err, checkErr, "a family that needs the table gets the error")
}
