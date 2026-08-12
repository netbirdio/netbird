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
	for _, env := range append(browserSessionEnvVars(), "XDG_SESSION_TYPE") {
		t.Setenv(env, "")
		os.Unsetenv(env)
	}

	assert.False(t, HasGraphicalSession(), "no session variables means no graphical session")

	tests := []struct {
		env      string
		value    string
		expected bool
	}{
		{env: "DISPLAY", value: ":0", expected: true},
		{env: "WAYLAND_DISPLAY", value: "wayland-0", expected: true},
		{env: "DESKTOP_SESSION", value: "gnome", expected: true},
		{env: "XDG_CURRENT_DESKTOP", value: "KDE", expected: true},
		{env: "BROWSER", value: "firefox", expected: true},
		{env: "XDG_SESSION_TYPE", value: "wayland", expected: true},
		{env: "XDG_SESSION_TYPE", value: "x11", expected: true},
		{env: "XDG_SESSION_TYPE", value: "tty", expected: false},
		{env: "XDG_SESSION_TYPE", value: "unspecified", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.env+"="+tt.value, func(t *testing.T) {
			t.Setenv(tt.env, tt.value)
			assert.Equal(t, tt.expected, HasGraphicalSession(), "%s=%s", tt.env, tt.value)
		})
	}
}
