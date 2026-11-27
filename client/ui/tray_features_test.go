//go:build !android && !ios && !freebsd && !js

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrayClientRoutesPrefersTheRunningEngine(t *testing.T) {
	enabled, disabled := false, true

	tests := []struct {
		name        string
		stored      bool
		running     *bool
		wantLocked  bool
		wantChanged bool
	}{
		{name: "no engine, stored enabled", stored: false, running: nil, wantLocked: false, wantChanged: false},
		{name: "no engine, stored disabled", stored: true, running: nil, wantLocked: true, wantChanged: false},
		{name: "engine disabled overrides stored enabled", stored: false, running: &disabled, wantLocked: true, wantChanged: true},
		{name: "engine enabled overrides stored disabled", stored: true, running: &enabled, wantLocked: false, wantChanged: true},
		{name: "engine matches stored", stored: true, running: &disabled, wantLocked: true, wantChanged: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tray := &Tray{clientRoutesDisabled: tc.stored}

			changed := tray.applyRunningClientRoutes(tc.running)
			_, _, locked := tray.featuresDisabled()

			assert.Equal(t, tc.wantChanged, changed, "change flag should report whether the effective state moved")
			assert.Equal(t, tc.wantLocked, locked, "effective client routes state should follow the running engine when known")
		})
	}
}

func TestTrayClientRoutesFallsBackToStoredWhenEngineStops(t *testing.T) {
	running := false
	tray := &Tray{clientRoutesDisabled: true}

	assert.True(t, tray.applyRunningClientRoutes(&running), "a running engine with routes on should unlock")
	assert.True(t, tray.applyRunningClientRoutes(nil), "losing the engine should fall back to the stored setting")

	_, _, locked := tray.featuresDisabled()
	assert.True(t, locked, "stored disabled setting should lock again once no engine runs")
}
