//go:build darwin && !ios

package server

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The agent's runtime parent has to be writable by its owner alone, or sticky.
// Anything else lets an unprivileged process win the race to create vnc-<uid>
// and receive the daemon's per-spawn token.
func TestWritableByOthers(t *testing.T) {
	tests := []struct {
		name string
		mode os.FileMode
		want bool
	}{
		{name: "owner only", mode: 0o700},
		{name: "owner writes, others read and traverse", mode: 0o755},
		{name: "group writable", mode: 0o770, want: true},
		{name: "world writable", mode: 0o707, want: true},
		{name: "world writable and sticky, as /tmp", mode: 0o777 | os.ModeSticky},
		{name: "group writable and sticky", mode: 0o770 | os.ModeSticky},
		// Set-uid and set-gid share the bit range with sticky in FileMode, so
		// they must not be mistaken for it.
		{name: "world writable and setgid", mode: 0o777 | os.ModeSetgid, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, writableByOthers(tt.mode))
		})
	}
}
