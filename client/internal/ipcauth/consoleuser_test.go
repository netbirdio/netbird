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

// A lookup that panics must read as "cannot confirm". The daemon installs no
// gRPC recovery interceptor, so without this the panic ends the process from
// inside the per-RPC authorization path.
func TestGuardConsoleLookupContainsAPanic(t *testing.T) {
	id := KnownForTest(Identity{UID: 1000})

	if guardConsoleLookup(id, func(Identity) bool {
		panic("pretending purego could not map a signature")
	}) {
		t.Fatal("a panicking lookup reported the caller as being at the console")
	}
}

// The guard must not swallow a real answer on its way out.
func TestGuardConsoleLookupPassesTheAnswerThrough(t *testing.T) {
	id := KnownForTest(Identity{UID: 1000})

	if !guardConsoleLookup(id, func(got Identity) bool {
		if got.UID != id.UID {
			t.Fatalf("lookup received uid %d, want %d", got.UID, id.UID)
		}
		return true
	}) {
		t.Fatal("a lookup that found the caller at the console reported false")
	}
	if guardConsoleLookup(id, func(Identity) bool { return false }) {
		t.Fatal("a lookup that found nobody reported true")
	}
}
