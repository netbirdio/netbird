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
	tableMissing := func() error {
		return errors.New("running [/sbin/ip6tables -t nat -S]: exit status 3: ip6tables v1.8.7: can't initialize ip6tables table `nat': Table does not exist (do you need to insmod?)")
	}
	listFails := func() error {
		return errors.New("running [/sbin/ip6tables -t nat -S]: exit status 4: Another app is currently holding the xtables lock")
	}
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

	ok, err = chainCheckResult(false, checkErr, true, listFails)
	assert.False(t, ok)
	assert.ErrorIs(t, err, checkErr, "a table that cannot be listed for another reason must not count as absent")

	ok, err = chainCheckResult(false, checkErr, false, tableMissing)
	assert.False(t, ok)
	assert.ErrorIs(t, err, checkErr, "a family that needs the table gets the error")
}
