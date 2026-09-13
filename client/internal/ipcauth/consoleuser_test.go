package ipcauth

import "testing"

// An identity the kernel never vouched for must not reach a console lookup at
// all: the zero Identity carries uid 0, which a platform lookup would
// otherwise compare against a root session.
func TestIsConsoleUserRejectsUnattestedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   Identity
	}{
		{"zero identity", Identity{}},
		{"unattested uid 0", Identity{UID: 0}},
		{"unattested uid", Identity{UID: 1000}},
		{"unattested sid", Identity{SID: "S-1-5-21-1-2-3-1001"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if IsConsoleUser(tc.id) {
				t.Fatal("an identity the kernel did not vouch for was reported as a console user")
			}
		})
	}
}
