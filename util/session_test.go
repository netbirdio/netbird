package util

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasGraphicalSession(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		assert.True(t, HasGraphicalSession(), "%s always has a graphical session", runtime.GOOS)
		return
	}

	// clear anything inherited from the session running the test, restored on cleanup
	for _, env := range append(browserSessionEnvVars(), envXDGSessionType) {
		t.Setenv(env, "")
		os.Unsetenv(env)
	}

	assert.False(t, HasGraphicalSession(), "no session variables means no graphical session")

	tests := []struct {
		env      string
		value    string
		expected bool
	}{
		{env: envDisplay, value: ":0", expected: true},
		{env: envWaylandDisplay, value: "wayland-0", expected: true},
		{env: envDesktopSession, value: "gnome", expected: true},
		{env: envXDGCurrentDesktop, value: "KDE", expected: true},
		{env: envBrowser, value: "firefox", expected: true},
		{env: envXDGSessionType, value: "wayland", expected: true},
		{env: envXDGSessionType, value: "x11", expected: true},
		{env: envXDGSessionType, value: "mir", expected: true},
		{env: envXDGSessionType, value: "tty", expected: false},
		{env: envXDGSessionType, value: "unspecified", expected: false},
		// an unrecognized type must not be read as a display: the device code flow works anyway
		{env: envXDGSessionType, value: "something-new", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.env+"="+tt.value, func(t *testing.T) {
			t.Setenv(tt.env, tt.value)
			assert.Equal(t, tt.expected, HasGraphicalSession(), "%s=%s", tt.env, tt.value)
		})
	}
}
