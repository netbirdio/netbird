package ipcauth

import (
	"context"
	"strconv"

	"google.golang.org/grpc/metadata"
)

// Metadata keys used by the local JSON gateway to forward the HTTP client's
// identity to the daemon.
const (
	mdFwdUID      = "x-netbird-fwd-uid"      // Unix
	mdFwdGID      = "x-netbird-fwd-gid"      // Unix
	mdFwdSID      = "x-netbird-fwd-sid"      // Windows user SID
	mdFwdGroup    = "x-netbird-fwd-group"    // Windows group SID (repeated)
	mdFwdElevated = "x-netbird-fwd-elevated" // Windows, "1" if elevated
)

// ForwardIdentityMetadata encodes an identity for the gateway to forward to the
// daemon.
func ForwardIdentityMetadata(id Identity) metadata.MD {
	if id.IsWindows() {
		md := metadata.MD{}
		md.Set(mdFwdSID, id.SID)
		if len(id.Groups) > 0 {
			md.Set(mdFwdGroup, id.Groups...)
		}
		if id.Elevated {
			md.Set(mdFwdElevated, "1")
		}
		return md
	}
	return metadata.Pairs(
		mdFwdUID, strconv.FormatUint(uint64(id.UID), 10),
		mdFwdGID, strconv.FormatUint(uint64(id.GID), 10),
	)
}

// forwardedIdentity extracts a forwarded identity from incoming gRPC metadata
func forwardedIdentity(ctx context.Context) (Identity, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return Identity{}, false
	}

	if sid := mdFirst(md, mdFwdSID); sid != "" {
		return Identity{
			SID:      sid,
			Groups:   md.Get(mdFwdGroup),
			Elevated: mdFirst(md, mdFwdElevated) == "1",
		}, true
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
	return id, true
}

func mdFirst(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}
