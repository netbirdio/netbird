package client

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	auth "github.com/netbirdio/netbird/relay/auth/hmac"
)

const (
	maxConcurrentServers = 7
)

var (
	connectionTimeout        = 30 * time.Second
	connectionSortingtimeout = 500 * time.Millisecond
)

type connResult struct {
	RelayClient *Client
	Url         string
	Err         error
	Latency     time.Duration
}

type ServerPicker struct {
	TokenStore *auth.TokenStore
	ServerURLs atomic.Value
	PeerID     string
}

func (sp *ServerPicker) PickServer(parentCtx context.Context) (*Client, error) {
	ctx, cancel := context.WithTimeout(parentCtx, connectionTimeout)
	defer cancel()

	totalServers := len(sp.ServerURLs.Load().([]string))

	connResultChan := make(chan connResult, totalServers)
	successChan := make(chan connResult, 1)
	concurrentLimiter := make(chan struct{}, maxConcurrentServers)

	log.Debugf("pick server from list: %v", sp.ServerURLs.Load().([]string))
	go sp.processConnResults(connResultChan, successChan)
	for _, url := range sp.ServerURLs.Load().([]string) {
		select {
		case concurrentLimiter <- struct{}{}:
			go func(url string) {
				defer func() {
					<-concurrentLimiter
				}()
				sp.startConnection(parentCtx, connResultChan, url)
			}(url)
		case cr, ok := <-successChan:
			if !ok {
				return nil, errors.New("failed to connect to any relay server: all attempts failed")
			}
			log.Infof("chosen home Relay server: %s with latency %s", cr.Url, cr.Latency)
			return cr.RelayClient, nil
		}
	}

	select {
	case cr, ok := <-successChan:
		if !ok {
			return nil, errors.New("failed to connect to any relay server: all attempts failed")
		}
		log.Infof("chosen home Relay server: %s with latency %s", cr.Url, cr.Latency)
		return cr.RelayClient, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("failed to connect to any relay server: %w", ctx.Err())
	}
}

func (sp *ServerPicker) startConnection(ctx context.Context, resultChan chan connResult, url string) {
	log.Infof("try to connecting to relay server: %s", url)
	relayClient := NewClient(ctx, url, sp.TokenStore, sp.PeerID)
	err := relayClient.Connect()
	resultChan <- connResult{
		RelayClient: relayClient,
		Url:         url,
		Err:         err,
		Latency:     relayClient.InitialConnectionTime,
	}
}

func (sp *ServerPicker) processConnResults(resultChan chan connResult, successChan chan connResult) {
	var hasSuccess bool
	var bestLatencyResult connResult
	bestLatencyResult.Latency = time.Hour
	processingCtx := context.Background()
	var processingCtxCancel context.CancelFunc
	for numOfResults := 0; numOfResults < cap(resultChan); numOfResults++ {
		var cr connResult
		select {
		case <-processingCtx.Done():
			log.Tracef("terminating Relay server sorting early")
			successChan <- bestLatencyResult
			close(successChan)
			successChan = nil // Prevent any more sending to successChan
			// Continue receiving connections to terminate any more
			cr = <-resultChan
		case cr = <-resultChan:
		}
		if cr.Err != nil {
			log.Tracef("failed to connect to Relay server: %s: %v", cr.Url, cr.Err)
			continue
		}
		log.Infof("connected to Relay server: %s with latency %s", cr.Url, cr.Latency)

		if hasSuccess {
			cr = lowestLatency(cr, bestLatencyResult)
		}

		// First successful connection, start a timer to return the result
		if !hasSuccess {
			processingCtx, processingCtxCancel = context.WithTimeout(processingCtx, connectionSortingtimeout)
		}
		hasSuccess = true
		bestLatencyResult = cr
	}

	processingCtxCancel()
	if successChan == nil {
		return
	}

	if bestLatencyResult.RelayClient != nil {
		successChan <- bestLatencyResult
	}
	close(successChan)
}

func lowestLatency(a, b connResult) connResult {
	if a.Latency > b.Latency {
		if err := b.RelayClient.Close(); err != nil {
			log.Errorf("failed to close connection to %s: %v", b.Url, err)
		}
		return a
	}

	if err := a.RelayClient.Close(); err != nil {
		log.Errorf("failed to close connection to %s: %v", a.Url, err)
	}
	return b
}
