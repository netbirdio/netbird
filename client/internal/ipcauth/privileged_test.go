package ipcauth

import "testing"

// The self rule is the one place privilege is granted to something other than the
// platform administrator, so its two guards matter: it must apply only when the
// daemon is itself unprivileged, and only to a caller with the daemon's identity.
func TestIsPrivilegedCaller_SelfRule(t *testing.T) {
	tests := []struct {
		name string
		// self stands in for the process the daemon runs as.
		self      Identity
		selfKnown bool
		caller    Identity
		want      bool
	}{
		{
			name:      "root is privileged whatever the daemon runs as",
			self:      Identity{UID: 1000},
			selfKnown: true,
			caller:    Identity{UID: 0},
			want:      true,
		},
		{
			name:      "an unprivileged daemon delegates to its own user (rootless container)",
			self:      Identity{UID: 1000},
			selfKnown: true,
			caller:    Identity{UID: 1000},
			want:      true,
		},
		{
			name:      "an unprivileged daemon delegates to nobody else",
			self:      Identity{UID: 1000},
			selfKnown: true,
			caller:    Identity{UID: 1001},
			want:      false,
		},
		{
			// The daemon is root on a normal install, so sharing its identity is
			// already covered by being root; nothing else may match.
			name:      "a root daemon delegates to nobody",
			self:      Identity{UID: 0},
			selfKnown: true,
			caller:    Identity{UID: 1000},
			want:      false,
		},
		{
			// Windows netstack mode: the daemon needs no administrator rights.
			name:      "an unprivileged windows daemon delegates to its own SID",
			self:      Identity{SID: "S-1-5-21-1-2-3-1001"},
			selfKnown: true,
			caller:    Identity{SID: "S-1-5-21-1-2-3-1001"},
			want:      true,
		},
		{
			name:      "an unprivileged windows daemon delegates to no other SID",
			self:      Identity{SID: "S-1-5-21-1-2-3-1001"},
			selfKnown: true,
			caller:    Identity{SID: "S-1-5-21-1-2-3-1002"},
			want:      false,
		},
		{
			// The UAC boundary: a filtered and a full token of the same account
			// carry the same SID but not the same power, so an elevated daemon must
			// never delegate to its own SID.
			name:      "an elevated windows daemon does not delegate to its own SID",
			self:      Identity{SID: "S-1-5-21-1-2-3-500", Elevated: true},
			selfKnown: true,
			caller:    Identity{SID: "S-1-5-21-1-2-3-500"},
			want:      false,
		},
		{
			name:      "LocalSystem is privileged on its own merits, not by delegation",
			self:      Identity{SID: sidLocalSystem},
			selfKnown: true,
			caller:    Identity{SID: sidLocalSystem},
			want:      true, // LocalSystem is privileged on its own merits
		},
		{
			name:      "identities of different kinds never match",
			self:      Identity{UID: 1000},
			selfKnown: true,
			caller:    Identity{SID: "S-1-5-21-1-2-3-1001"},
			want:      false,
		},
		{
			name:      "an unknown self identity delegates to nobody",
			self:      Identity{},
			selfKnown: false,
			caller:    Identity{UID: 1000},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prevID, prevKnown, prevDelegate := selfIdentity, selfKnown, selfMayDelegate
			t.Cleanup(func() { selfIdentity, selfKnown, selfMayDelegate = prevID, prevKnown, prevDelegate })

			selfIdentity, selfKnown = tt.self, tt.selfKnown
			selfMayDelegate = tt.selfKnown && mayDelegate(tt.self)

			if got := IsPrivilegedCaller(tt.caller); got != tt.want {
				t.Fatalf("IsPrivilegedCaller(%v) with daemon %v = %t, want %t",
					tt.caller, tt.self, got, tt.want)
			}
		})
	}
}

// The real process must never accidentally delegate: a test binary running as a
// normal user is unprivileged, so it may match itself, but nothing else.
func TestIsPrivilegedCaller_ThisProcess(t *testing.T) {
	id, err := CurrentProcessIdentity()
	if err != nil {
		t.Skipf("cannot read this process's identity: %v", err)
	}

	// This process is always allowed to act as itself: either it is privileged, or
	// it is unprivileged and therefore delegates to its own identity.
	if !IsPrivilegedCaller(id) {
		t.Errorf("this process %v was refused its own identity", id)
	}

	// A caller that is neither root nor this process must be refused, whatever
	// this process happens to be.
	other := Identity{UID: id.UID + 1}
	if id.IsWindows() {
		other = Identity{SID: id.SID + "9"}
	}
	if IsPrivilegedCaller(other) {
		t.Errorf("an unrelated identity %v was treated as privileged", other)
	}
}

// The shared service accounts are held by unrelated services, so a daemon running
// as one of them must not extend its authority to every process with that SID.
func TestMayDelegate(t *testing.T) {
	tests := []struct {
		name string
		self Identity
		want bool
	}{
		{name: "unprivileged unix user", self: Identity{UID: 1000}, want: true},
		{name: "root", self: Identity{UID: 0}, want: false},
		{name: "unprivileged windows user", self: Identity{SID: "S-1-5-21-1-2-3-1001"}, want: true},
		{name: "elevated windows user", self: Identity{SID: "S-1-5-21-1-2-3-1001", Elevated: true}, want: false},
		{name: "local system", self: Identity{SID: sidLocalSystem}, want: false},
		{name: "local service", self: Identity{SID: sidLocalService}, want: false},
		{name: "network service", self: Identity{SID: sidNetworkService}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mayDelegate(tt.self); got != tt.want {
				t.Errorf("mayDelegate(%+v) = %v, want %v", tt.self, got, tt.want)
			}
		})
	}
}
