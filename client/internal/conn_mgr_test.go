package internal

import (
	"os"
	"testing"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
)

func TestResolveLazyForce(t *testing.T) {
	tests := []struct {
		name   string
		env    string
		envSet bool
		mdm    lazyconn.State
		want   lazyForce
	}{
		{name: "env unset, mdm unset -> defer to management", mdm: lazyconn.StateUnset, want: lazyForceNone},
		{name: "env on -> force on", env: "on", envSet: true, mdm: lazyconn.StateUnset, want: lazyForceOn},
		{name: "env off -> force off", env: "off", envSet: true, mdm: lazyconn.StateUnset, want: lazyForceOff},
		{name: "env unset, mdm on -> force on", mdm: lazyconn.StateOn, want: lazyForceOn},
		{name: "env unset, mdm off -> force off", mdm: lazyconn.StateOff, want: lazyForceOff},
		{name: "env on beats mdm off", env: "on", envSet: true, mdm: lazyconn.StateOff, want: lazyForceOn},
		{name: "env off beats mdm on", env: "off", envSet: true, mdm: lazyconn.StateOn, want: lazyForceOff},
		{name: "unrecognized env, mdm on -> mdm wins", env: "auto", envSet: true, mdm: lazyconn.StateOn, want: lazyForceOn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(lazyconn.EnvLazyConn, tt.env)
			if !tt.envSet {
				os.Unsetenv(lazyconn.EnvLazyConn)
			}

			if got := resolveLazyForce(tt.mdm); got != tt.want {
				t.Fatalf("resolveLazyForce(%v) = %v, want %v", tt.mdm, got, tt.want)
			}
		})
	}
}
