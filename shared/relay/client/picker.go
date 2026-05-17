package client

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	auth "github.com/netbirdio/netbird/shared/relay/auth/hmac"
)

const (
	maxConcurrentServers     = 7
	defaultConnectionTimeout = 30 * time.Second
)

type connResult struct {
	RelayClient *Client
	Url         string
	Err         error
}

type ServerPicker struct {
	TokenStore *auth.TokenStore
	// ServerURLs holds the legacy flat list of relay URLs, kept for callers
	// that don't yet thread through transport hints. Endpoints, when set, is
	// the source of truth — ServerURLs is derived from it.
	ServerURLs        atomic.Value
	Endpoints         atomic.Value // []ServerEndpoint
	PeerID            string
	MTU               uint16
	ConnectionTimeout time.Duration
}

// loadEndpoints returns the per-endpoint list, falling back to a URL-only
// projection of ServerURLs if no endpoints have been set yet (older callers
// that still call UpdateServerURLs without the hint-aware path).
func (sp *ServerPicker) loadEndpoints() []ServerEndpoint {
	if v := sp.Endpoints.Load(); v != nil {
		if eps, ok := v.([]ServerEndpoint); ok && len(eps) > 0 {
			return eps
		}
	}
	if v := sp.ServerURLs.Load(); v != nil {
		if urls, ok := v.([]string); ok {
			return EndpointsFromURLs(urls)
		}
	}
	return nil
}

func (sp *ServerPicker) PickServer(parentCtx context.Context) (*Client, error) {
	ctx, cancel := context.WithTimeout(parentCtx, sp.ConnectionTimeout)
	defer cancel()

	endpoints := sp.loadEndpoints()
	totalServers := len(endpoints)

	connResultChan := make(chan connResult, totalServers)
	successChan := make(chan connResult, 1)
	concurrentLimiter := make(chan struct{}, maxConcurrentServers)

	log.Debugf("pick server from list: %d endpoint(s)", totalServers)
	for _, ep := range endpoints {
		// todo check if we have a successful connection so we do not need to connect to other servers
		concurrentLimiter <- struct{}{}
		go func(ep ServerEndpoint) {
			defer func() {
				<-concurrentLimiter
			}()
			sp.startConnection(parentCtx, connResultChan, ep)
		}(ep)
	}

	go sp.processConnResults(connResultChan, successChan)

	select {
	case cr, ok := <-successChan:
		if !ok {
			return nil, errors.New("failed to connect to any relay server: all attempts failed")
		}
		log.Infof("chosen home Relay server: %s", cr.Url)
		return cr.RelayClient, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("failed to connect to any relay server: %w", ctx.Err())
	}
}

func (sp *ServerPicker) startConnection(ctx context.Context, resultChan chan connResult, ep ServerEndpoint) {
	log.Infof("try to connecting to relay server: %s (transports=%v)", ep.URL, ep.Transports)
	relayClient := NewClient(ep.URL, sp.TokenStore, sp.PeerID, sp.MTU)
	if len(ep.Transports) > 0 {
		relayClient.SetTransportHint(ep.Transports)
	}
	err := relayClient.Connect(ctx)
	resultChan <- connResult{
		RelayClient: relayClient,
		Url:         ep.URL,
		Err:         err,
	}
}

func (sp *ServerPicker) processConnResults(resultChan chan connResult, successChan chan connResult) {
	var hasSuccess bool
	for numOfResults := 0; numOfResults < cap(resultChan); numOfResults++ {
		cr := <-resultChan
		if cr.Err != nil {
			log.Tracef("failed to connect to Relay server: %s: %v", cr.Url, cr.Err)
			continue
		}
		log.Infof("connected to Relay server: %s", cr.Url)

		if hasSuccess {
			log.Infof("closing unnecessary Relay connection to: %s", cr.Url)
			if err := cr.RelayClient.Close(); err != nil {
				log.Errorf("failed to close connection to %s: %v", cr.Url, err)
			}
			continue
		}

		hasSuccess = true
		successChan <- cr
	}
	close(successChan)
}
