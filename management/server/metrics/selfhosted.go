// Package metrics gather anonymous information about the usage of NetBird management
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/management/server"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// PayloadEvent identifies an event type
	PayloadEvent = "self-hosted stats"
	// payloadEndpoint metrics defaultEndpoint to send anonymous data
	payloadEndpoint = "https://metrics.netbird.io"
	// defaultPushInterval default interval to push metrics
	defaultPushInterval = 24 * time.Hour
	// requestTimeout http request timeout
	requestTimeout = 30 * time.Second
)

type getTokenResponse struct {
	PublicAPIToken string `json:"public_api_token"`
}

type pushPayload struct {
	APIKey     string     `json:"api_key"`
	DistinctID string     `json:"distinct_id"`
	Event      string     `json:"event"`
	Properties properties `json:"properties"`
	Timestamp  time.Time  `json:"timestamp"`
}

// properties metrics to push
type properties map[string]interface{}

// DataSource metric data source
type DataSource interface {
	GetAllAccounts() []*server.Account
}

// ConnManager peer connection manager that holds state for current active connections
type ConnManager interface {
	GetAllConnectedPeers() map[string]struct{}
}

// Worker metrics collector and pusher
type Worker struct {
	ctx         context.Context
	id          string
	dataSource  DataSource
	connManager ConnManager
	startupTime time.Time
	lastRun     time.Time
}

// NewWorker returns a metrics worker
func NewWorker(ctx context.Context, id string, dataSource DataSource, connManager ConnManager) *Worker {
	currentTime := time.Now()
	return &Worker{
		ctx:         ctx,
		id:          id,
		dataSource:  dataSource,
		connManager: connManager,
		startupTime: currentTime,
		lastRun:     currentTime,
	}
}

// Run runs the metrics worker
func (w *Worker) Run() {
	pushTicker := time.NewTicker(defaultPushInterval)
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-pushTicker.C:
			err := w.sendMetrics()
			if err != nil {
				log.Error(err)
			}
		}
	}
}

func (w *Worker) sendMetrics() error {
	ctx, cancel := context.WithTimeout(w.ctx, requestTimeout)
	defer cancel()

	apiKey, err := getAPIKey(ctx)
	if err != nil {
		return err
	}

	payload := w.generatePayload(apiKey)

	payloadString, err := buildMetricsPayload(payload)
	if err != nil {
		return err
	}

	httpClient := http.Client{}

	exportJobReq, err := createPostRequest(ctx, payloadEndpoint+"/capture/", payloadString)
	if err != nil {
		return fmt.Errorf("unable to create metrics post request %v", err)
	}

	jobResp, err := httpClient.Do(exportJobReq)
	if err != nil {
		return fmt.Errorf("unable to push metrics %v", err)
	}

	defer func() {
		err = jobResp.Body.Close()
		if err != nil {
			log.Errorf("error while closing update metrics response body: %v", err)
		}
	}()

	if jobResp.StatusCode != 200 {
		return fmt.Errorf("unable to push anonymous metrics, got statusCode %d", jobResp.StatusCode)
	}

	log.Infof("sent anonymous metrics, next push will happen in %s. "+
		"You can disable these metrics by running with flag --disable-anonymous-metrics,"+
		" see more information at https://netbird.io/docs/FAQ/metrics-collection", defaultPushInterval)

	return nil
}

func (w *Worker) generatePayload(apiKey string) pushPayload {
	properties := w.generateProperties()

	return pushPayload{
		APIKey:     apiKey,
		DistinctID: w.id,
		Event:      PayloadEvent,
		Properties: properties,
		Timestamp:  time.Now(),
	}
}

func (w *Worker) generateProperties() properties {
	var (
		uptime             float64
		accounts           int
		users              int
		peers              int
		setupKeysUsage     int
		activePeersLastDay int
		osPeers            map[string]int
		userPeers          int
		rules              int
		groups             int
		routes             int
		nameservers        int
		version            string
	)
	start := time.Now()
	metricsProperties := make(properties)
	osPeers = make(map[string]int)
	uptime = time.Since(w.startupTime).Seconds()
	connections := w.connManager.GetAllConnectedPeers()
	version = system.NetbirdVersion()

	for _, account := range w.dataSource.GetAllAccounts() {
		accounts++
		users = users + len(account.Users)
		rules = rules + len(account.Rules)
		groups = groups + len(account.Groups)
		routes = routes + len(account.Routes)
		nameservers = nameservers + len(account.NameServerGroups)

		for _, key := range account.SetupKeys {
			setupKeysUsage = setupKeysUsage + key.UsedTimes
		}

		for _, peer := range account.Peers {
			peers++
			if peer.SetupKey != "" {
				userPeers++
			}

			osKey := strings.ToLower(fmt.Sprintf("peer_os_%s", peer.Meta.GoOS))
			osCount := osPeers[osKey]
			osPeers[osKey] = osCount + 1

			_, connected := connections[peer.Key]
			if connected || peer.Status.LastSeen.After(w.lastRun) {
				activePeersLastDay++
				osActiveKey := osKey + "_active"
				osActiveCount := osPeers[osActiveKey]
				osPeers[osActiveKey] = osActiveCount + 1
			}
		}
	}

	metricsProperties["uptime"] = uptime
	metricsProperties["accounts"] = accounts
	metricsProperties["users"] = users
	metricsProperties["peers"] = peers
	metricsProperties["setup_keys_usage"] = setupKeysUsage
	metricsProperties["active_peers_last_day"] = activePeersLastDay
	metricsProperties["user_peers"] = userPeers
	metricsProperties["rules"] = rules
	metricsProperties["groups"] = groups
	metricsProperties["routes"] = routes
	metricsProperties["nameservers"] = nameservers
	metricsProperties["version"] = version

	for os, count := range osPeers {
		metricsProperties[os] = count
	}

	metricsProperties["metric_generation_time"] = time.Since(start).Milliseconds()

	return metricsProperties
}

func getAPIKey(ctx context.Context) (string, error) {

	httpClient := http.Client{}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, payloadEndpoint+"/GetToken", nil)
	if err != nil {
		return "", fmt.Errorf("unable to create request for metrics public api token %v", err)
	}
	response, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("unable to request metrics public api token %v", err)
	}

	defer func() {
		err = response.Body.Close()
		if err != nil {
			log.Errorf("error while closing metrics token response body: %v", err)
		}
	}()

	if response.StatusCode != 200 {
		return "", fmt.Errorf("unable to retrieve metrics token, statusCode %d", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("coudln't get metrics token response; %v", err)
	}

	var tokenResponse getTokenResponse

	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return "", fmt.Errorf("coudln't parse metrics public api token; %v", err)
	}

	return tokenResponse.PublicAPIToken, nil
}

func buildMetricsPayload(payload pushPayload) (string, error) {
	str, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("unable to marshal metrics payload, got err: %v", err)
	}
	return string(str), nil
}

func createPostRequest(ctx context.Context, endpoint string, payloadStr string) (*http.Request, error) {
	reqURL := endpoint

	payload := strings.NewReader(payloadStr)

	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Add("content-type", "application/json")

	return req, nil
}
