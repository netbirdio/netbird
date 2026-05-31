//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// Autostart is the Wails-bound facade over Wails' AutostartManager. The OS
// login-item registration (launchd/SMAppService on macOS, HKCU\…\Run on
// Windows, an XDG .desktop on Linux) is the single source of truth — IsEnabled
// reads it directly, so nothing is mirrored to the preferences file. Enable
// registers the running executable to launch at login with no extra arguments;
// the app comes up hidden into the tray, same as a normal launch.
type Autostart struct {
	mgr *application.AutostartManager
}

// NewAutostart wraps the application's AutostartManager (app.Autostart).
func NewAutostart(mgr *application.AutostartManager) *Autostart {
	return &Autostart{mgr: mgr}
}

// Supported reports whether autostart can be toggled on this platform. The
// frontend hides the toggle entirely when this is false.
func (a *Autostart) Supported(_ context.Context) bool {
	_, err := a.mgr.Status()
	return !errors.Is(err, application.ErrAutostartNotSupported)
}

// IsEnabled reports whether the app is currently registered to launch at
// login. On an unsupported platform it returns false without error so the
// frontend can render the toggle off (gated by Supported).
func (a *Autostart) IsEnabled(_ context.Context) (bool, error) {
	enabled, err := a.mgr.IsEnabled()
	if err != nil {
		if errors.Is(err, application.ErrAutostartNotSupported) {
			return false, nil
		}
		return false, fmt.Errorf("read autostart state: %w", err)
	}
	return enabled, nil
}

// SetEnabled registers (enabled) or removes (disabled) the launch-at-login
// entry. The change takes effect on the next login, not immediately.
func (a *Autostart) SetEnabled(_ context.Context, enabled bool) error {
	if enabled {
		if err := a.mgr.Enable(); err != nil {
			return fmt.Errorf("enable autostart: %w", err)
		}
		return nil
	}
	if err := a.mgr.Disable(); err != nil {
		return fmt.Errorf("disable autostart: %w", err)
	}
	return nil
}
