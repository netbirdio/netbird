package ipcauth

import (
	"context"
	"strconv"

	"google.golang.org/grpc/metadata"
)

// Metadata keys used by the local JSON gateway to forward the HTTP client's
// identity to the daemon. Trusted by the interceptor ONLY when the gRPC peer is
// itself the daemon (self/privileged) — i.e. the loopback gateway — so a direct
// gRPC caller cannot forge them.
const (
	mdFwdUID = "x-netbird-fwd-uid"
	mdFwdGID = "x-netbird-fwd-gid"
	mdFwdPID = "x-netbird-fwd-pid"
)

// ForwardIdentityMetadata encodes a Unix identity for the gateway to forward to
// the daemon. Windows identities are not forwarded (the gateway cannot read a
// pipe token for an HTTP client); nil is returned in that case.
func ForwardIdentityMetadata(id Identity) metadata.MD {
	if id.IsWindows() {
		return nil
	}
	md := metadata.Pairs(
		mdFwdUID, strconv.FormatUint(uint64(id.UID), 10),
		mdFwdGID, strconv.FormatUint(uint64(id.GID), 10),
	)
	if id.HasPID {
		md.Set(mdFwdPID, strconv.FormatInt(int64(id.PID), 10))
	}
	return md
}

// forwardedIdentity extracts a forwarded Unix identity from incoming gRPC
// metadata, if present and well-formed.
func forwardedIdentity(ctx context.Context) (Identity, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return Identity{}, false
	}
	uidStr := mdFirst(md, mdFwdUID)
	if uidStr == "" {
		return Identity{}, false
	}
	uid, err := strconv.ParseUint(uidStr, 10, 32)
	if err != nil {
		return Identity{}, false
	}
	id := Identity{UID: uint32(uid)}
	if g := mdFirst(md, mdFwdGID); g != "" {
		if v, err := strconv.ParseUint(g, 10, 32); err == nil {
			id.GID = uint32(v)
		}
	}
	if p := mdFirst(md, mdFwdPID); p != "" {
		if v, err := strconv.ParseInt(p, 10, 32); err == nil {
			id.PID = int32(v)
			id.HasPID = true
		}
	}
	return id, true
}

func mdFirst(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}
