package roundtrip

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/embed"
)

const deviceNamePrefix = "ingress-"

// NetBird provides an http.RoundTripper implementation
// backed by underlying NetBird connections.
type NetBird struct {
	mgmtAddr string
	logger   *log.Logger

	clientsMux sync.RWMutex
	clients    map[string]*embed.Client
}

func NewNetBird(mgmtAddr string, logger *log.Logger) *NetBird {
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &NetBird{
		mgmtAddr: mgmtAddr,
		logger:   logger,
		clients:  make(map[string]*embed.Client),
	}
}

func (n *NetBird) AddPeer(ctx context.Context, domain, key string) error {
	client, err := embed.New(embed.Options{
		DeviceName:    deviceNamePrefix + domain,
		ManagementURL: n.mgmtAddr,
		SetupKey:      key,
		LogOutput:     io.Discard,
		BlockInbound:  true,
	})
	if err != nil {
		return fmt.Errorf("create netbird client: %w", err)
	}

	// Attempt to start the client in the background, if this fails
	// then it is not ideal, but it isn't the end of the world because
	// we will try to start the client again before we use it.
	go func() {
		startCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		err = client.Start(startCtx)
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			n.logger.Debug("netbird client timed out")
			// This is not ideal, but we will try again later.
			return
		case err != nil:
			n.logger.WithField("domain", domain).WithError(err).Error("Unable to start netbird client, will try again later.")
		}
	}()

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
	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
	}
	n.clientsMux.RLock()
	client, exists := n.clients[host]
	// Immediately unlock after retrieval here rather than defer to avoid
	// the call to client.Do blocking other clients being used whilst one
	// is in use.
	n.clientsMux.RUnlock()
	if !exists {
		return nil, fmt.Errorf("no peer connection found for host: %s", host)
	}

	// Attempt to start the client, if the client is already running then
	// it will return an error that we ignore, if this hits a timeout then
	// this request is unprocessable.
	startCtx, cancel := context.WithTimeout(req.Context(), 3*time.Second)
	defer cancel()
	err = client.Start(startCtx)
	switch {
	case errors.Is(err, embed.ErrClientAlreadyStarted):
		break
	case err != nil:
		return nil, fmt.Errorf("start netbird client: %w", err)
	}

	n.logger.WithFields(log.Fields{
		"host":       host,
		"url":        req.URL.String(),
		"requestURI": req.RequestURI,
		"method":     req.Method,
	}).Debug("running roundtrip for peer connection")

	// Create a new transport using the client dialer and perform the roundtrip.
	// We do this instead of using the client HTTPClient to avoid issues around
	// client request validation that do not work with the reverse proxied
	// requests.
	// Other values are simply copied from the http.DefaultTransport which the
	// standard reverse proxy implementation would have used.
	// TODO: tune this transport for our needs.
	return (&http.Transport{
		DialContext:           client.DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}).RoundTrip(req)
}
