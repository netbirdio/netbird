package server

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// Certificate posture reads the store of the account that owns the profile being
// connected, so the owner comes from that profile rather than the active state.
func TestProfileOwner(t *testing.T) {
	own, other := "uid:1000", "sid:S-1-5-21-1-2-3-1001"
	wantOwn := "1000"
	if runtime.GOOS == "windows" {
		own, other = other, own
		wantOwn = "S-1-5-21-1-2-3-1001"
	}

	tests := []struct {
		name      string
		owners    []string
		wantOwner string
		wantKnown bool
	}{
		{name: "an unowned profile leaves it to the console user", owners: nil, wantOwner: "", wantKnown: true},
		{name: "the owner principal's value names the account", owners: []string{own}, wantOwner: wantOwn, wantKnown: true},
		{name: "an owner of the other platform is unknown", owners: []string{other}, wantKnown: false},
		{name: "a group is unknown", owners: []string{"gid:1000"}, wantKnown: false},
		{name: "an unparseable owner is unknown", owners: []string{"alice"}, wantKnown: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, known := profileOwner(&profilemanager.Config{Owners: tt.owners})
			assert.Equal(t, tt.wantKnown, known, "known")
			assert.Equal(t, tt.wantOwner, owner, "owner")
		})
	}
}
