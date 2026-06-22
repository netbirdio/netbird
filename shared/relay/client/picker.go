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
	TokenStore        *auth.TokenStore
	ServerURLs        atomic.Value
	PeerID            string
	MTU               uint16
	ConnectionTimeout time.Duration
	TransportFallback *transportFallback
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
	for _, url := range sp.ServerURLs.Load().([]string) {
		// todo check if we have a successful connection so we do not need to connect to other servers
		concurrentLimiter <- struct{}{}
		go func(url string) {
			defer func() {
				<-concurrentLimiter
			}()
			sp.startConnection(parentCtx, connResultChan, url)
		}(url)
	}

	go sp.processConnResults(connResultChan, successChan, errChan)

	select {
	case cr, ok := <-successChan:
		if !ok {
			return nil, <-errChan
		}
		log.Infof("chosen home Relay server: %s", cr.Url)
		return cr.RelayClient, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("connect to relay server: %w", ctx.Err())
	}
}

func (sp *ServerPicker) startConnection(ctx context.Context, resultChan chan connResult, url string) {
	log.Infof("try to connecting to relay server: %s", url)
	relayClient := NewClient(url, sp.TokenStore, sp.PeerID, sp.MTU)
	relayClient.SetTransportFallback(sp.TransportFallback)
	err := relayClient.Connect(ctx)
	resultChan <- connResult{
		RelayClient: relayClient,
		Url:         url,
		Err:         err,
	}
}

func (sp *ServerPicker) processConnResults(resultChan chan connResult, successChan chan connResult, errChan chan error) {
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
