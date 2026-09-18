package certproof

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConsoleUser_OnlyADesktopSessionCanBeValidated(t *testing.T) {
	tests := []struct {
		name    string
		user    ConsoleUser
		desktop bool
	}{
		{"logged in user", ConsoleUser{Name: "maycon", UID: 501, GID: 20}, true},
		{"login window as root", ConsoleUser{Name: "root", UID: 0}, false},
		{"login window by name", ConsoleUser{Name: "loginwindow", UID: 0}, false},
		{"named user still at uid 0", ConsoleUser{Name: "admin", UID: 0}, false},
		{"no console user", ConsoleUser{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.desktop, tt.user.hasDesktop(), "only a real desktop session offers a login keychain")
		})
	}
}

// CurrentConsoleUser runs against the real SystemConfiguration framework. A machine with
// a desktop open must report a non-root user; a headless runner must report none.
func TestCurrentConsoleUser_AgreesWithItself(t *testing.T) {
	user, ok := CurrentConsoleUser()
	if !ok {
		t.Log("no console user, running headless")
		return
	}
	assert.NotEmpty(t, user.Name, "a console user must have a name")
	assert.NotZero(t, user.UID, "a desktop session never belongs to uid 0")
	assert.True(t, user.hasDesktop(), "a reported console user must be a desktop session")
}
