//go:build !windows

package ipcauth

import (
	"strconv"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/internal/shell"
)

const groupCacheTTL = 30 * time.Second

// NewDefaultGroupResolver returns an NSS-aware group resolver, owners resolve
// correctly for LDAP/AD users under CGO_ENABLED=0. Results are cached briefly.
func NewDefaultGroupResolver() GroupResolver {
	return &nssResolver{byUID: make(map[uint32]gidCacheEntry)}
}

type gidCacheEntry struct {
	gids map[uint32]struct{}
	at   time.Time
}

type nssResolver struct {
	mu    sync.Mutex
	byUID map[uint32]gidCacheEntry
}

func (r *nssResolver) CallerGIDs(id Identity) map[uint32]struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()

	if e, ok := r.byUID[id.UID]; ok && time.Since(e.at) < groupCacheTTL {
		return e.gids
	}
	gids := resolveGIDs(id.UID)
	r.byUID[id.UID] = gidCacheEntry{gids: gids, at: time.Now()}
	return gids
}

func resolveGIDs(uid uint32) map[uint32]struct{} {
	out := make(map[uint32]struct{})
	u, err := shell.GetUserFromGetent(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return out
	}
	ids, err := shell.GroupIdsWithFallback(u)
	if err != nil {
		return out
	}
	for _, s := range ids {
		if g, err := strconv.ParseUint(s, 10, 32); err == nil {
			out[uint32(g)] = struct{}{}
		}
	}
	return out
}

func (r *nssResolver) GroupNameGID(name string) (uint32, bool) {
	g, err := shell.LookupGroupWithGetent(name)
	if err != nil {
		return 0, false
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(gid), true
}
