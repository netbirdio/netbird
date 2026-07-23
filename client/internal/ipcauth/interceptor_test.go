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
	o       Ownership
	claimed bool
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
	up    = servicePath + "Up"
	list  = servicePath + "ListProfiles"
	unkwn = servicePath + "SomeFutureMethod"
)

func TestInterceptorAuthorize(t *testing.T) {
	const selfUID = 4000

	tests := []struct {
		name     string
		own      Ownership
		resolver GroupResolver
		ctx      context.Context
		method   string
		wantErr  bool
	}{
		{"no identity denies", Ownership{}, nil, context.Background(), up, true},
		{"root allowed", Ownership{}, nil, ctxWith(Identity{UID: 0}), up, false},
		{"daemon-self allowed", Ownership{}, nil, ctxWith(Identity{UID: selfUID}), up, false},
		{"shared allows any", Ownership{Shared: true}, nil, ctxWith(Identity{UID: 1234}), up, false},
		{"uid owner allowed", Ownership{Owners: []string{"uid:1000"}}, nil, ctxWith(Identity{UID: 1000}), up, false},
		{"non-owner denied", Ownership{Owners: []string{"uid:1000"}}, nil, ctxWith(Identity{UID: 2000}), up, true},
		{"handler-authorized bypass", Ownership{Owners: []string{"uid:1000"}}, nil, ctxWith(Identity{UID: 2000}), list, false},
		{"unknown method gated", Ownership{Owners: []string{"uid:1000"}}, nil, ctxWith(Identity{UID: 2000}), unkwn, true},
		{"primary gid owner", Ownership{Owners: []string{"gid:5000"}}, nil, ctxWith(Identity{UID: 2000, GID: 5000}), up, false},
		{"group-name owner via resolver", Ownership{Owners: []string{"group:admins"}},
			mockResolver{names: map[string]uint32{"admins": 5000}, gids: map[uint32]struct{}{5000: {}}},
			ctxWith(Identity{UID: 2000, GID: 42}), up, false},
		{"windows sid owner", Ownership{Owners: []string{"sid:S-1-5-21-9"}}, nil,
			ctxWith(Identity{SID: "S-1-5-21-9"}), up, false},
		{"windows group-sid owner", Ownership{Owners: []string{"sid:S-1-5-32-544"}}, nil,
			ctxWith(Identity{SID: "S-1-5-21-1", Groups: []string{"S-1-5-32-544"}}), up, false},
		{"windows elevated privileged", Ownership{}, nil,
			ctxWith(Identity{SID: "S-1-5-21-1", Elevated: true}), up, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &Interceptor{policy: &mockPolicy{o: tt.own}, resolver: tt.resolver, selfUID: selfUID}
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

	// Gateway (peer == daemon-self) forwards a non-owner client → denied as that client.
	i := &Interceptor{policy: &mockPolicy{o: owners}, selfUID: selfUID}
	assert.Error(t, i.authorize(withFwd(selfUID, 2000), up))

	// Gateway forwards the owner → allowed.
	assert.NoError(t, i.authorize(withFwd(selfUID, 1000), up))

	// A non-privileged direct caller's forwarded metadata is IGNORED (can't forge):
	// caller uid 2000 forwarding uid:1000 is still treated as 2000 → denied.
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
