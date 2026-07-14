package internal

import (
	"context"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
)

const dnsActivationPollInterval = 50 * time.Millisecond

// dnsPeerActivator wakes lazy-connection peers from the DNS resolution path. It
// implements dns/local.PeerActivator. ConnMgr is not thread-safe (guarded by
// the engine's syncMsgMux) while DNS queries run on their own goroutines, so
// activation runs under that mutex; the connection wait runs without it.
type dnsPeerActivator struct {
	connMgr   *ConnMgr
	peerStore *peerstore.Store
	status    *peer.Status
	mu        *sync.Mutex
}

// ActivatePeersByIP triggers wake-up for the peer(s) owning ips and waits until
// one is connected or ctx expires. Unknown or already-connected IPs are skipped,
// so the steady-state (warm) path adds no latency.
func (a *dnsPeerActivator) ActivatePeersByIP(ctx context.Context, ips []string) {
	if a == nil || a.connMgr == nil {
		return
	}

	var pending []string
	a.mu.Lock()
	for _, ip := range ips {
		st, ok := a.status.PeerStateByIP(ip)
		if !ok || st.ConnStatus == peer.StatusConnected {
			continue
		}
		conn, ok := a.peerStore.PeerConn(st.PubKey)
		if !ok {
			continue
		}
		a.connMgr.ActivatePeer(ctx, conn)
		pending = append(pending, ip)
	}
	a.mu.Unlock()

	if len(pending) == 0 {
		return
	}
	a.waitConnected(ctx, pending)
}

// waitConnected blocks until any of ips reports a connected peer or ctx expires.
func (a *dnsPeerActivator) waitConnected(ctx context.Context, ips []string) {
	ticker := time.NewTicker(dnsActivationPollInterval)
	defer ticker.Stop()
	for {
		for _, ip := range ips {
			if st, ok := a.status.PeerStateByIP(ip); ok && st.ConnStatus == peer.StatusConnected {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
