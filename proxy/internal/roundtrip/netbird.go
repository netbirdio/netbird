package roundtrip

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/netbirdio/netbird/client/embed"
)

const deviceNamePrefix = "ingress-"

// NetBird provides an http.RoundTripper implementation
// backed by underlying NetBird connections.
type NetBird struct {
	mgmtAddr string

	clientsMux sync.RWMutex
	clients    map[string]*embed.Client
}

func NewNetBird(mgmtAddr string) *NetBird {
	return &NetBird{
		mgmtAddr: mgmtAddr,
		clients:  make(map[string]*embed.Client),
	}
}

func (n *NetBird) AddPeer(ctx context.Context, domain, key string) error {
	client, err := embed.New(embed.Options{
		DeviceName:    deviceNamePrefix + domain,
		ManagementURL: n.mgmtAddr,
		SetupKey:      key,
	})
	if err != nil {
		return fmt.Errorf("create netbird client: %w", err)
	}
	if err := client.Start(ctx); err != nil {
		return fmt.Errorf("start netbird client: %w", err)
	}
	n.clientsMux.Lock()
	defer n.clientsMux.Unlock()
	n.clients[domain] = client
	return nil
}

func (n *NetBird) RemovePeer(ctx context.Context, domain string) error {
	n.clientsMux.RLock()
	client, exists := n.clients[domain]
	n.clientsMux.RUnlock()
	if !exists {
		// Mission failed successfully!
		return nil
	}
	if err := client.Stop(ctx); err != nil {
		return fmt.Errorf("stop netbird client: %w", err)
	}
	n.clientsMux.Lock()
	defer n.clientsMux.Unlock()
	delete(n.clients, domain)
	return nil
}

func (n *NetBird) RoundTrip(req *http.Request) (*http.Response, error) {
	n.clientsMux.RLock()
	client, exists := n.clients[req.Host]
	// Immediately unlock after retrieval here rather than defer to avoid
	// the call to client.Do blocking other clients being used whilst one
	// is in use.
	n.clientsMux.RUnlock()
	if !exists {
		return nil, fmt.Errorf("no peer connection found for host: %s", req.Host)
	}
	return client.NewHTTPClient().Do(req)
}
