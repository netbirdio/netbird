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
	// attempt is the index of the dial in the server list.
	attempt int
}

type ServerPicker struct {
	TokenStore        *auth.TokenStore
	ServerURLs        atomic.Value
	PeerID            string
	MTU               uint16
	ConnectionTimeout time.Duration
	TransportFallback *transportFallback
	NetEvents         NetEvents
}

func (sp *ServerPicker) PickServer(parentCtx context.Context) (*Client, error) {
	ctx, cancel := context.WithTimeout(parentCtx, sp.ConnectionTimeout)
	defer cancel()

	totalServers := len(sp.ServerURLs.Load().([]string))

	connResultChan := make(chan connResult, totalServers)
	successChan := make(chan connResult, 1)
	errChan := make(chan error, 1)
	concurrentLimiter := make(chan struct{}, maxConcurrentServers)

	log.Debugf("pick server from list: %v", sp.ServerURLs.Load().([]string))
	// Each dial gets its own context: the chosen client is bound to its context
	// for its whole lifetime, so only the dials that lost the race are cancelled
	// and the chosen client's context is released when the client closes.
	urls := sp.ServerURLs.Load().([]string)
	dialCancels := make([]context.CancelFunc, len(urls))
	dialCtxs := make([]context.Context, len(urls))
	for i := range urls {
		dialCtxs[i], dialCancels[i] = context.WithCancel(parentCtx)
	}
	for i, url := range urls {
		// todo check if we have a successful connection so we do not need to connect to other servers
		concurrentLimiter <- struct{}{}
		go func(attempt int, url string) {
			defer func() {
				<-concurrentLimiter
			}()
			sp.startConnection(dialCtxs[attempt], connResultChan, attempt, url)
		}(i, url)
	}

	// A dial that finished after the chosen one would register the peer on its
	// relay and close right away, which that relay reports as the peer going
	// offline, so the others are cancelled as soon as one is chosen.
	onChosen := func(cr connResult) {
		cancelDials(dialCancels, cr.attempt)
		cr.RelayClient.releaseContextOnClose(dialCancels[cr.attempt])
	}
	go sp.processConnResults(connResultChan, successChan, errChan, onChosen)

	select {
	case cr, ok := <-successChan:
		if !ok {
			cancelDials(dialCancels, -1)
			return nil, <-errChan
		}
		instanceURL, serverIP, err := cr.RelayClient.serverInstanceAddress()
		if err != nil {
			log.Infof("chosen home Relay server: %s, instance address unavailable: %v", cr.Url, err)
			return cr.RelayClient, nil
		}
		log.Infof("chosen home Relay server: %s, instance URL: %s, server IP: %s", cr.Url, instanceURL, serverIP)
		return cr.RelayClient, nil
	case <-ctx.Done():
		cancelDials(dialCancels, -1)
		return nil, fmt.Errorf("connect to relay server: %w", ctx.Err())
	}
}

// cancelDials cancels every dial except the attempt to keep; -1 cancels all.
func cancelDials(dialCancels []context.CancelFunc, keep int) {
	for attempt, cancel := range dialCancels {
		if attempt != keep {
			cancel()
		}
	}
}

func (sp *ServerPicker) startConnection(ctx context.Context, resultChan chan connResult, attempt int, url string) {
	log.Infof("try to connecting to relay server: %s", url)
	relayClient := NewClient(url, sp.TokenStore, sp.PeerID, sp.MTU)
	relayClient.SetTransportFallback(sp.TransportFallback)
	relayClient.netEvents = sp.NetEvents
	err := relayClient.Connect(ctx)
	resultChan <- connResult{
		RelayClient: relayClient,
		Url:         url,
		Err:         err,
		attempt:     attempt,
	}
}

func (sp *ServerPicker) processConnResults(resultChan chan connResult, successChan chan connResult, errChan chan error, onChosen func(connResult)) {
	var hasSuccess bool
	var errs []error
	for numOfResults := 0; numOfResults < cap(resultChan); numOfResults++ {
		cr := <-resultChan
		if cr.Err != nil {
			log.Tracef("failed to connect to Relay server: %s: %v", cr.Url, cr.Err)
			errs = append(errs, cr.Err)
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
		onChosen(cr)
		successChan <- cr
	}
	if !hasSuccess {
		errChan <- pickErr(errs)
	}
	close(successChan)
}

// pickErr combines per-server connection failures into a single error.
func pickErr(errs []error) error {
	if len(errs) == 0 {
		return errors.New("no relay server available")
	}
	return errors.Join(errs...)
}
