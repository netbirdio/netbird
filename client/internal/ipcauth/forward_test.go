package ipcauth

import (
	"context"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// transportCtx builds a request context as the daemon's transport credentials
// would: the identity of whoever opened the socket, plus whatever metadata the
// request carried.
func transportCtx(id Identity, md metadata.MD) context.Context {
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: AuthInfo{
			CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
			Identity:       id,
		},
	})
	if md != nil {
		ctx = metadata.NewIncomingContext(ctx, md)
	}
	return ctx
}

var (
	root       = Identity{UID: 0}
	unprivUser = Identity{UID: 1000, GID: 1000}
)

// asDaemon pins which identity counts as this process for the duration of a test.
// Without it the test binary's own uid decides, which silently changes what
// "the gateway" means.
func asDaemon(t *testing.T, id Identity) {
	t.Helper()
	prevID, prevKnown, prevDelegate := selfIdentity, selfKnown, selfMayDelegate
	t.Cleanup(func() { selfIdentity, selfKnown, selfMayDelegate = prevID, prevKnown, prevDelegate })
	selfIdentity, selfKnown = id, true
	selfMayDelegate = !id.IsPrivileged()
}

func TestCallerIdentity_DirectConnections(t *testing.T) {
	t.Run("no transport credentials is not an identity", func(t *testing.T) {
		if _, ok := CallerIdentity(context.Background()); ok {
			t.Fatal("a caller with no credentials must not be identified")
		}
	})

	t.Run("a direct caller is its transport identity", func(t *testing.T) {
		id, ok := CallerIdentity(transportCtx(unprivUser, nil))
		if !ok || id.UID != 1000 {
			t.Fatalf("got %v ok=%t, want uid 1000", id, ok)
		}
	})

	// The whole point of honouring forwarded metadata only from a privileged
	// transport peer: an unprivileged caller can set any metadata it likes on its
	// own connection to the daemon socket.
	t.Run("an unprivileged caller cannot forge an identity", func(t *testing.T) {
		asDaemon(t, root)
		forged := metadata.Pairs(mdFwd, "1", mdFwdUID, "0", mdFwdGID, "0")
		id, ok := CallerIdentity(transportCtx(unprivUser, forged))
		if !ok {
			t.Fatal("caller should still be identified, as itself")
		}
		if id.IsPrivileged() || id.UID != 1000 {
			t.Fatalf("forged metadata was believed: got %v", id)
		}
	})
}

func TestCallerIdentity_GatewayForwarding(t *testing.T) {
	t.Run("the gateway's client identity is used, not the gateway's own", func(t *testing.T) {
		asDaemon(t, root)
		md := ForwardIdentityMetadata(unprivUser, true)
		id, ok := CallerIdentity(transportCtx(root, md))
		if !ok {
			t.Fatal("forwarded identity should be usable")
		}
		if id.IsPrivileged() || id.UID != 1000 {
			t.Fatalf("got %v, want the forwarded uid 1000 and not privileged", id)
		}
	})

	t.Run("a privileged gateway client stays privileged", func(t *testing.T) {
		asDaemon(t, root)
		md := ForwardIdentityMetadata(root, true)
		id, ok := CallerIdentity(transportCtx(root, md))
		if !ok || !id.IsPrivileged() {
			t.Fatalf("got %v ok=%t, want a privileged identity", id, ok)
		}
	})

	// A JSON socket the gateway cannot read peer credentials from (a TCP socket,
	// say) must not make every request look like the daemon itself.
	t.Run("an unreadable client identity is unknown, not the daemon", func(t *testing.T) {
		asDaemon(t, root)
		md := ForwardIdentityMetadata(Identity{}, false)
		if _, ok := CallerIdentity(transportCtx(root, md)); ok {
			t.Fatal("a forwarded request with no identity must not be identified")
		}
	})

	// grpc-gateway turns Grpc-Metadata-<key> headers into gRPC metadata and joins
	// them ahead of its annotators' values. If an HTTP client's header survived
	// that, this is the shape the daemon would see: the attacker's uid 0 first,
	// the real uid second. The gateway filters those headers out, and reading a
	// duplicated key as unknown makes the daemon safe even if it did not.
	t.Run("a duplicated key from an injected header is not believed", func(t *testing.T) {
		asDaemon(t, root)
		md := metadata.MD{}
		md.Append(mdFwd, "1")
		md.Append(mdFwdUID, "0")    // injected by the HTTP client
		md.Append(mdFwdUID, "1000") // appended by the gateway's annotator
		if id, ok := CallerIdentity(transportCtx(root, md)); ok {
			t.Fatalf("injected uid was accepted: got %v", id)
		}
	})

	t.Run("a duplicated marker is not believed either", func(t *testing.T) {
		asDaemon(t, root)
		md := metadata.MD{}
		md.Append(mdFwd, "1")
		md.Append(mdFwd, "1")
		md.Append(mdFwdUID, "1000")
		// A repeated marker must not be read as "not forwarded": that would
		// authorize the request as the transport peer, which on the gateway's
		// connection is the daemon itself.
		if id, ok := CallerIdentity(transportCtx(root, md)); ok {
			t.Fatalf("a duplicated marker was believed: got %v", id)
		}
	})

	// The layers in front of this (the gateway's header matcher, and its
	// interceptor replacing every forwarding key) are what keep outside metadata
	// from arriving at all. The proof is what the daemon can check for itself, and
	// it is the only defence that works for a value whose legitimate shape is
	// indistinguishable from an injected one: a lone group SID, or "elevated".
	t.Run("forwarding metadata without this process's proof is refused", func(t *testing.T) {
		asDaemon(t, root)
		for name, md := range map[string]metadata.MD{
			"no proof":    metadata.Pairs(mdFwd, "1", mdFwdUID, "0"),
			"wrong proof": metadata.Pairs(mdFwd, "1", mdFwdUID, "0", mdFwdProof, "deadbeef"),
			"windows identity without a proof": metadata.Pairs(mdFwd, "1",
				mdFwdSID, "S-1-5-21-1-2-3-1001", mdFwdGroup, sidAdministrators, mdFwdElevated, "1"),
		} {
			t.Run(name, func(t *testing.T) {
				if id, ok := CallerIdentity(transportCtx(root, md)); ok {
					t.Fatalf("unstamped forwarding metadata was believed: got %v", id)
				}
			})
		}
	})

	// A caller that reaches the gateway cannot see the proof, so it cannot append
	// a group of its own to a genuine forwarded identity: doing so would have to
	// go through the interceptor, which replaces the whole set.
	t.Run("a group appended to a stamped identity does not survive the interceptor", func(t *testing.T) {
		asDaemon(t, root)
		injected := metadata.MD{}
		injected.Append(mdFwdGroup, sidAdministrators)

		ctx := WithForwardedIdentity(metadata.NewOutgoingContext(context.Background(), injected),
			Identity{SID: "S-1-5-21-1-2-3-1001"}, true)
		out, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Fatal("no outgoing metadata")
		}
		if groups := out.Get(mdFwdGroup); len(groups) != 0 {
			t.Fatalf("injected group survived: %v", groups)
		}
	})
}

func TestIsReservedForwardKey(t *testing.T) {
	for _, key := range forwardKeys {
		if !IsReservedForwardKey(key) {
			t.Errorf("%q must be reserved", key)
		}
	}

	// grpc-gateway canonicalises header names, so the check has to be
	// case-insensitive.
	if !IsReservedForwardKey("X-Netbird-Fwd-Uid") {
		t.Error("the check must be case-insensitive")
	}

	for _, key := range []string{"authorization", "x-netbird", "x-netbird-fwd-uid-extra", ""} {
		if IsReservedForwardKey(key) {
			t.Errorf("%q must not be reserved", key)
		}
	}
}

func TestForwardIdentityMetadata_AlwaysMarksForwarded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		id    Identity
		known bool
	}{
		{"known unix identity", unprivUser, true},
		{"unknown identity", Identity{}, false},
		{"windows identity", Identity{SID: "S-1-5-21-1-2-3-1001", Elevated: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			md := ForwardIdentityMetadata(tc.id, tc.known)
			if got := md.Get(mdFwd); len(got) != 1 || got[0] != "1" {
				t.Fatalf("marker = %v, want exactly one \"1\"", got)
			}
		})
	}
}
