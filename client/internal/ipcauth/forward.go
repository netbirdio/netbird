package ipcauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/grpc/metadata"
)

// Metadata keys the local JSON gateway uses to forward the identity of its own
// HTTP client to the daemon. The gateway runs inside the daemon process and
// re-dials the daemon over the control socket, so without forwarding every
// JSON request would appear to come from the daemon itself.
const (
	// mdFwd marks a request as forwarded by the JSON gateway. It is always
	// set, even when the gateway could not read its client's identity, so the
	// daemon can tell "no identity available" apart from "not forwarded".
	mdFwd         = "x-netbird-fwd"
	mdFwdUID      = "x-netbird-fwd-uid"      // Unix user ID
	mdFwdGID      = "x-netbird-fwd-gid"      // Unix primary group ID
	mdFwdSID      = "x-netbird-fwd-sid"      // Windows user SID
	mdFwdGroup    = "x-netbird-fwd-group"    // Windows group SID, repeated
	mdFwdElevated = "x-netbird-fwd-elevated" // Windows, "1" when elevated

	// mdFwdProof proves the forwarded identity was stamped by this process. The
	// gateway runs inside the daemon, so a secret held in memory is available to
	// the only legitimate producer and to nothing else.
	mdFwdProof = "x-netbird-fwd-proof"
)

// forwardKeys is every metadata key the gateway sets. An HTTP client must never
// be able to supply one itself: see IsReservedForwardKey.
var forwardKeys = []string{mdFwd, mdFwdUID, mdFwdGID, mdFwdSID, mdFwdGroup, mdFwdElevated, mdFwdProof}

// forwardProof authenticates the gateway's forwarding metadata. It is generated
// once per daemon process and never leaves it: it is not written to disk, not
// logged, and not sent anywhere except over the daemon's own control socket to
// itself.
//
// Without it, trusting a forwarded identity rests on every layer in front of it
// stripping incoming forwarding keys, and on each key's value shape being
// distinguishable from an injected one. A single injected group SID or an
// injected "elevated" flag has the same shape as a legitimate one, so no
// cardinality rule can catch it. Requiring the proof means metadata that did not
// come from this process is refused whatever it contains.
var forwardProof = mustForwardProof()

func mustForwardProof() string {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Continuing would leave the forwarded path authenticated by a
		// predictable value, which is worse than not starting.
		panic(fmt.Sprintf("generate identity forwarding proof: %v", err))
	}
	return hex.EncodeToString(buf[:])
}

// IsReservedForwardKey reports whether a gRPC metadata key belongs to the
// gateway's identity forwarding, and therefore must be dropped when it arrives
// from outside.
//
// grpc-gateway maps "Grpc-Metadata-<key>" request headers into gRPC metadata and
// joins them ahead of the values its own annotators add. Without dropping these,
// an HTTP client could hand the daemon "x-netbird-fwd-uid: 0" and be believed,
// because the daemon trusts forwarded metadata when the transport peer is the
// (privileged) gateway.
func IsReservedForwardKey(key string) bool {
	key = strings.ToLower(key)
	return slices.Contains(forwardKeys, key)
}

// ForwardIdentityMetadata encodes an HTTP client's identity for the JSON
// gateway to forward to the daemon. When known is false only the marker is
// set, which makes the daemon treat the caller as unidentified rather than as
// the daemon itself.
func ForwardIdentityMetadata(id Identity, known bool) metadata.MD {
	md := metadata.MD{}
	md.Set(mdFwd, "1")
	md.Set(mdFwdProof, forwardProof)
	if !known {
		return md
	}

	if id.IsWindows() {
		md.Set(mdFwdSID, id.SID)
		if len(id.Groups) > 0 {
			md.Set(mdFwdGroup, id.Groups...)
		}
		if id.Elevated {
			md.Set(mdFwdElevated, "1")
		}
		return md
	}

	md.Set(mdFwdUID, strconv.FormatUint(uint64(id.UID), 10))
	md.Set(mdFwdGID, strconv.FormatUint(uint64(id.GID), 10))
	return md
}

// CallerIdentity returns the identity to authorize a request against. For a
// direct connection that is the transport peer's kernel identity. For a
// request relayed by the local JSON gateway it is the identity the gateway
// forwarded, since the transport peer is then the daemon itself.
//
// A forwarded identity is only honoured when the transport peer is the daemon's
// own identity and the metadata carries this process's forwarding proof, so
// forged forwarding metadata gains a caller nothing. A forwarded request that
// carries no identity is reported as unidentified, never as the daemon.
//
// The second return value is false when no identity could be established, and
// callers MUST fail closed in that case.
func CallerIdentity(ctx context.Context) (Identity, bool) {
	id, ok := IdentityFromContext(ctx)
	if !ok {
		return Identity{}, false
	}

	// A forwarding key that arrives more than once did not come from the gateway
	// alone, so nothing about the request can be trusted to describe its caller.
	// Refusing outright matters because the alternative reading, "not forwarded",
	// would authorize the request as the transport peer, which on the gateway's
	// connection is the daemon itself.
	if duplicatedForwardKey(ctx) {
		return Identity{}, false
	}

	forwarded := isForwarded(ctx)

	// Our own process on the other end of the socket is the JSON gateway, the only
	// thing that dials the daemon from inside it. Such a call must carry a
	// forwarded identity; without one there is no caller to authorize, and
	// treating it as the daemon would authorize whatever reached the JSON socket.
	// Only Linux reports the peer PID, so this is a belt on top of the gateway's
	// interceptor rather than the sole guarantee.
	if id.PID != 0 && int(id.PID) == selfPID && !forwarded {
		return Identity{}, false
	}

	// Only the gateway's own connection may speak for someone else. Being
	// privileged is not enough and not the point: the gateway runs inside the
	// daemon, so it dials as the daemon's identity whatever user that is, which
	// also covers a rootless container.
	if !forwarded || !IsDaemonSelf(id) {
		return id, true
	}

	// Speaking for someone else additionally requires the proof only this process
	// holds. Refusing is the only safe reading: the transport peer here is the
	// daemon itself, so falling back to it would authorize the request as the
	// daemon. This is also what makes the forwarded values trustworthy once
	// accepted, so they need no shape checks of their own.
	if !authenticForward(ctx) {
		return Identity{}, false
	}

	return forwardedIdentity(ctx)
}

// duplicatedForwardKey reports whether any forwarding key carries more than one
// value. The gateway's interceptor sets each key exactly once and replaces what
// was already there, so a repeat means a second source supplied it.
func duplicatedForwardKey(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	for _, key := range forwardKeys {
		// Group SIDs are legitimately repeated; the rest identify the caller.
		if key == mdFwdGroup {
			continue
		}
		if len(md.Get(key)) > 1 {
			return true
		}
	}
	return false
}

// authenticForward reports whether the request carries this process's forwarding
// proof, which only the in-process JSON gateway can supply.
func authenticForward(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	got := mdSingle(md, mdFwdProof)
	return subtle.ConstantTimeCompare([]byte(got), []byte(forwardProof)) == 1
}

// isForwarded reports whether the request carries the JSON gateway marker.
func isForwarded(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	return mdSingle(md, mdFwd) != ""
}

// forwardedIdentity decodes the identity the JSON gateway attached.
func forwardedIdentity(ctx context.Context) (Identity, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return Identity{}, false
	}

	if sid := mdSingle(md, mdFwdSID); sid != "" {
		return Identity{
			SID: sid,
			// Repeated by design, one value per group, and only reachable once
			// the forwarding proof has been verified.
			Groups:   md.Get(mdFwdGroup),
			Elevated: mdSingle(md, mdFwdElevated) == "1",
		}, true
	}

	uid, err := strconv.ParseUint(mdSingle(md, mdFwdUID), 10, 32)
	if err != nil {
		return Identity{}, false
	}

	id := Identity{UID: uint32(uid)}
	if gid, err := strconv.ParseUint(mdSingle(md, mdFwdGID), 10, 32); err == nil {
		id.GID = uint32(gid)
	}
	return id, true
}

// mdSingle returns the value of a forwarded key only when exactly one was
// supplied. The gateway's interceptor sets each key exactly once, so more than one
// value means something else also supplied it, and the whole identity is treated as
// unknown rather than picking a winner. Defence in depth behind the gateway's
// header filter.
func mdSingle(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) == 1 {
		return v[0]
	}
	return ""
}

// WithForwardedIdentity stamps id onto a context's outgoing metadata for the JSON
// gateway's call to the daemon, replacing any forwarding keys already present so
// values supplied from outside cannot survive alongside it.
//
// This is deliberately not done with runtime.WithMetadata: grpc-gateway skips its
// annotators entirely when no request header maps to metadata ("if len(pairs) == 0
// { return ctx, nil, nil }", runtime/context.go), which an HTTP/1.0 request with no
// Host header over a unix socket achieves. The daemon would then see an unmarked
// call whose transport peer is the daemon's own identity, and authorize it as the
// daemon. A client interceptor runs for every RPC regardless of headers.
func WithForwardedIdentity(ctx context.Context, id Identity, known bool) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.MD{}
	} else {
		md = md.Copy()
	}

	for _, key := range forwardKeys {
		delete(md, key)
	}
	for key, values := range ForwardIdentityMetadata(id, known) {
		md[key] = values
	}

	return metadata.NewOutgoingContext(ctx, md)
}
