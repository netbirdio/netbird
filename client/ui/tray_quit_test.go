//go:build !android && !ios && !freebsd && !js

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/mdm"
)

func TestKeepConnectedOnQuit(t *testing.T) {
	managedOff := mdm.NewPolicy(map[string]any{mdm.KeyKeepConnectedOnQuit: false})
	managedOn := mdm.NewPolicy(map[string]any{mdm.KeyKeepConnectedOnQuit: true})
	unmanaged := mdm.NewPolicy(map[string]any{mdm.KeyMTU: int64(1300)})

	assert.False(t, keepConnectedOnQuit(managedOff, true), "the policy wins over the user's choice")
	assert.True(t, keepConnectedOnQuit(managedOn, false), "the policy wins over the user's choice")
	assert.True(t, keepConnectedOnQuit(unmanaged, true), "without the key the user's choice applies")
	assert.False(t, keepConnectedOnQuit(unmanaged, false), "without the key the user's choice applies")
}
