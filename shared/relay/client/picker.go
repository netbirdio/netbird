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
	// transport is the connection that still has to authenticate; nil when Err is set.
	transport *transportDial
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
	// Only the dial of the transport connections is raced. The auth message
	// registers the peer on the relay, so it is sent on the chosen one alone: a
	// relay never sees a peer from a dial that lost, and closing that dial cannot
	// be reported as the peer going offline.
	onChosen := func(cr connResult) {
		cancelDials(dialCancels, cr.attempt)
		cr.RelayClient.releaseContextOnClose(dialCancels[cr.attempt])
	}
	go sp.processConnResults(connResultChan, successChan, errChan, onChosen)

	for i, url := range urls {
		// todo check if we have a successful connection so we do not need to connect to other servers
		select {
		case concurrentLimiter <- struct{}{}:
		case <-ctx.Done():
			for ; i < len(urls); i++ {
				connResultChan <- connResult{Url: urls[i], Err: ctx.Err(), attempt: i}
			}
			continue
		}
		go func(attempt int, url string) {
			defer func() {
				<-concurrentLimiter
			}()
			sp.startConnection(dialCtxs[attempt], connResultChan, attempt, url)
		}(i, url)
	}

	select {
	case cr, ok := <-successChan:
		if !ok {
			cancelDials(dialCancels, -1)
			return nil, <-errChan
		}
		return chosenClient(cr), nil
	case <-ctx.Done():
		// A dial that succeeded as the timeout fired is already the chosen one.
		select {
		case cr, ok := <-successChan:
			if ok {
				return chosenClient(cr), nil
			}
		default:
		}
		cancelDials(dialCancels, -1)
		return nil, fmt.Errorf("connect to relay server: %w", ctx.Err())
	}
}

func chosenClient(cr connResult) *Client {
	instanceURL, serverIP, err := cr.RelayClient.serverInstanceAddress()
	if err != nil {
		log.Infof("chosen home Relay server: %s, instance address unavailable: %v", cr.Url, err)
		return cr.RelayClient
	}
	log.Infof("chosen home Relay server: %s, instance URL: %s, server IP: %s", cr.Url, instanceURL, serverIP)
	return cr.RelayClient
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
	td, err := relayClient.dialTransport(ctx)
	resultChan <- connResult{
		RelayClient: relayClient,
		Url:         url,
		Err:         err,
		transport:   td,
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

		if hasSuccess {
			log.Infof("dropping unnecessary Relay connection to: %s", cr.Url)
			cr.transport.discard()
			continue
		}

		if err := cr.RelayClient.connectOn(cr.transport); err != nil {
			log.Tracef("failed to authenticate on Relay server: %s: %v", cr.Url, err)
			errs = append(errs, err)
			continue
		}
		log.Infof("connected to Relay server: %s", cr.Url)

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
