//go:build !android && !ios && !freebsd && !js

package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/ui/services"
)

func TestConnectMenuStateDaemonUnavailable(t *testing.T) {
	state := connectMenuState(false, services.StatusDaemonUnavailable)
	require.False(t, state.hidden)
	require.True(t, state.enabled)
}
