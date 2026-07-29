package ipcauth

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type mockPolicy struct {
	o             Ownership // active profile ownership
	daemon        Ownership // daemon-wide ownership
	claimed       bool
	daemonClaimed bool
}

func (m *mockPolicy) ActiveProfileOwnership() Ownership { return m.o }

// ClaimActiveProfileOwnerIfUnowned records a claim and marks the profile owned.
func (m *mockPolicy) ClaimActiveProfileOwnerIfUnowned(id Identity) (bool, error) {
	if len(m.o.Owners) == 0 && !m.o.Shared {
		m.o.Owners = []string{OwnerPrincipalForIdentity(id)}
		m.claimed = true
		return true, nil
	}
	return false, nil
}

func (m *mockPolicy) DaemonOwnership() Ownership { return m.daemon }

// ClaimDaemonOwnerIfUnowned records a daemon claim and marks the daemon owned.
func (m *mockPolicy) ClaimDaemonOwnerIfUnowned(id Identity) (bool, error) {
	if len(m.daemon.Owners) == 0 && !m.daemon.Shared {
		m.daemon.Owners = []string{OwnerPrincipalForIdentity(id)}
		m.daemonClaimed = true
		return true, nil
	}
	return false, nil
}

type mockResolver struct {
	gids  map[uint32]struct{}
	names map[string]uint32
}

func (m mockResolver) CallerGIDs(Identity) map[uint32]struct{} { return m.gids }
func (m mockResolver) GroupNameGID(n string) (uint32, bool)    { g, ok := m.names[n]; return g, ok }

func ctxWith(id Identity) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: AuthInfo{Identity: id}})
}

const (
	up       = servicePath + "Up"
	list     = servicePath + "ListProfiles"
	unkwn    = servicePath + "SomeFutureMethod"
	down     = servicePath + "Down"
	statusm  = servicePath + "Status"
	addp     = servicePath + "AddProfile"
	switchp  = servicePath + "SwitchProfile"
	addowner = servicePath + "AddOwner"
	sharep   = servicePath + "ShareProfile"
)

func TestInterceptorAuthorize(t *testing.T) {
	const selfUID = 4000

	tests := []struct {
		name     string
		own      Ownership // active profile ownership
		daemon   Ownership // daemon-wide ownership
		resolver GroupResolver
		ctx      context.Context
		method   string
		wantErr  bool
	}{
		// Default gate (active profile ownership).
		{"no identity denies", Ownership{}, Ownership{}, nil, context.Background(), up, true},
		{"root allowed", Ownership{}, Ownership{}, nil, ctxWith(Identity{UID: 0}), up, false},
		{"daemon-self allowed", Ownership{}, Ownership{}, nil, ctxWith(Identity{UID: selfUID}), up, false},
		{"shared allows any", Ownership{Shared: true}, Ownership{}, nil, ctxWith(Identity{UID: 1234}), up, false},
		{"uid owner allowed", Ownership{Owners: []string{"uid:1000"}}, Ownership{}, nil, ctxWith(Identity{UID: 1000}), up, false},
		{"non-owner denied", Ownership{Owners: []string{"uid:1000"}}, Ownership{Owners: []string{"uid:1000"}}, nil, ctxWith(Identity{UID: 2000}), up, true},
		{"unknown method gated", Ownership{Owners: []string{"uid:1000"}}, Ownership{}, nil, ctxWith(Identity{UID: 2000}), unkwn, true},
		{"primary gid owner", Ownership{Owners: []string{"gid:5000"}}, Ownership{}, nil, ctxWith(Identity{UID: 2000, GID: 5000}), up, false},
		{"group-name owner via resolver", Ownership{Owners: []string{"group:admins"}}, Ownership{},
			mockResolver{names: map[string]uint32{"admins": 5000}, gids: map[uint32]struct{}{5000: {}}},
			ctxWith(Identity{UID: 2000, GID: 42}), up, false},
		{"windows sid owner", Ownership{Owners: []string{"sid:S-1-5-21-9"}}, Ownership{}, nil,
			ctxWith(Identity{SID: "S-1-5-21-9"}), up, false},
		{"windows group-sid owner", Ownership{Owners: []string{"sid:S-1-5-32-544"}}, Ownership{}, nil,
			ctxWith(Identity{SID: "S-1-5-21-1", Groups: []string{"S-1-5-32-544"}}), up, false},
		{"windows elevated privileged", Ownership{}, Ownership{}, nil,
			ctxWith(Identity{SID: "S-1-5-21-1", Elevated: true}), up, false},

		// Profile tier (handler self-authorizes, bypass).
		{"list bypasses gate", Ownership{Owners: []string{"uid:1000"}}, Ownership{}, nil, ctxWith(Identity{UID: 2000}), list, false},
		{"switch-profile bypasses gate", Ownership{Owners: []string{"uid:1000"}}, Ownership{}, nil, ctxWith(Identity{UID: 2000}), switchp, false},

		// Owner tier (daemon-wide ownership), independent of the active profile.
		{"down by daemon owner allowed", Ownership{Owners: []string{"uid:9"}}, Ownership{Owners: []string{"uid:1000"}}, nil, ctxWith(Identity{UID: 1000}), down, false},
		{"down by non-owner denied", Ownership{}, Ownership{Owners: []string{"uid:1000"}}, nil, ctxWith(Identity{UID: 2000}), down, true},
		{"status by non-owner denied", Ownership{}, Ownership{Owners: []string{"uid:1000"}}, nil, ctxWith(Identity{UID: 2000}), statusm, true},
		{"add by daemon owner allowed", Ownership{}, Ownership{Owners: []string{"uid:1000"}}, nil, ctxWith(Identity{UID: 1000}), addp, false},
		{"add by non-owner denied", Ownership{}, Ownership{Owners: []string{"uid:1000"}}, nil, ctxWith(Identity{UID: 2000}), addp, true},
		{"owner-tier TOFU claims unowned daemon", Ownership{}, Ownership{}, nil, ctxWith(Identity{UID: 2000}), down, false},

		// Owner-set mutations gate on daemon ownership, not the active profile.
		{"add-owner by daemon owner allowed", Ownership{Owners: []string{"uid:9"}}, Ownership{Owners: []string{"uid:1000"}}, nil, ctxWith(Identity{UID: 1000}), addowner, false},
		{"add-owner by active-profile owner (non daemon owner) denied", Ownership{Owners: []string{"uid:2000"}}, Ownership{Owners: []string{"uid:1000"}}, nil, ctxWith(Identity{UID: 2000}), addowner, true},
		{"share by active-profile owner (non daemon owner) denied", Ownership{Owners: []string{"uid:2000"}}, Ownership{Owners: []string{"uid:1000"}}, nil, ctxWith(Identity{UID: 2000}), sharep, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &Interceptor{policy: &mockPolicy{o: tt.own, daemon: tt.daemon}, resolver: tt.resolver, selfUID: selfUID}
			err := i.authorize(tt.ctx, tt.method)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, codes.PermissionDenied, status.Code(err))
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestInterceptorForwardedIdentity verifies the JSON-gateway trust model: a
// self/privileged transport peer (the loopback gateway) may forward a real
// client identity, but a non-privileged caller cannot forge it.
func TestInterceptorForwardedIdentity(t *testing.T) {
	const selfUID = 4000
	owners := Ownership{Owners: []string{"uid:1000"}}

	withFwd := func(peerUID, fwdUID uint32) context.Context {
		ctx := ctxWith(Identity{UID: peerUID})
		return metadata.NewIncomingContext(ctx, metadata.Pairs(mdFwdUID, itoa(fwdUID)))
	}

	// Gateway forwards a non-owner client: denied as that client.
	i := &Interceptor{policy: &mockPolicy{o: owners}, selfUID: selfUID}
	assert.Error(t, i.authorize(withFwd(selfUID, 2000), up))

	// Gateway forwards the owner: allowed.
	assert.NoError(t, i.authorize(withFwd(selfUID, 1000), up))

	// A non-privileged direct caller's forwarded metadata: denied
	assert.Error(t, i.authorize(withFwd(2000, 1000), up))
}

func itoa(u uint32) string {
	return strconv.FormatUint(uint64(u), 10)
}

// TestInterceptorTOFU verifies an unowned, non-shared profile is claimed by the
// first non-privileged caller, and a different caller is then denied.
func TestInterceptorTOFU(t *testing.T) {
	policy := &mockPolicy{o: Ownership{}} // unowned
	i := &Interceptor{policy: policy, resolver: nil, selfUID: 4000}

	// First caller (uid 1000) claims via TOFU.
	err := i.authorize(ctxWith(Identity{UID: 1000}), up)
	assert.NoError(t, err)
	assert.True(t, policy.claimed, "first caller should claim ownership")
	assert.Equal(t, []string{"uid:1000"}, policy.o.Owners)

	// A different caller is now denied (profile owned by uid 1000).
	err = i.authorize(ctxWith(Identity{UID: 2000}), up)
	assert.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}
