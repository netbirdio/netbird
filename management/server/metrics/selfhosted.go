// Package metrics gather anonymous information about the usage of NetBird management
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server"
	nbversion "github.com/netbirdio/netbird/version"
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
			w.lastRun = time.Now()
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
		expirationEnabled  int
		users              int
		serviceUsers       int
		pats               int
		peers              int
		peersSSHEnabled    int
		setupKeysUsage     int
		activePeersLastDay int
		osPeers            map[string]int
		userPeers          int
		rules              int
		rulesProtocol      map[string]int
		rulesDirection     map[string]int
		groups             int
		routes             int
		nameservers        int
		uiClient           int
		version            string
		peerActiveVersions []string
		osUIClients        map[string]int
	)
	start := time.Now()
	metricsProperties := make(properties)
	osPeers = make(map[string]int)
	osUIClients = make(map[string]int)
	uptime = time.Since(w.startupTime).Seconds()
	connections := w.connManager.GetAllConnectedPeers()
	version = nbversion.NetbirdVersion()

	for _, account := range w.dataSource.GetAllAccounts() {
		accounts++

		if account.Settings.PeerLoginExpirationEnabled {
			expirationEnabled++
		}

		rules = rules + len(account.Rules)
		groups = groups + len(account.Groups)
		routes = routes + len(account.Routes)
		nameservers = nameservers + len(account.NameServerGroups)

		for _, rule := range account.Rules {
			policyRule := rule.ToPolicyRule()
			rulesProtocol[string(policyRule.Protocol)]++
			if policyRule.Bidirectional {
				rulesDirection["bidirectional"]++
			} else {
				rulesDirection["oneway"]++
			}
		}

		for _, user := range account.Users {
			if user.IsServiceUser {
				serviceUsers++
			} else {
				users++
			}
			pats = +len(user.PATs)
		}

		for _, key := range account.SetupKeys {
			setupKeysUsage = setupKeysUsage + key.UsedTimes
		}

		for _, peer := range account.Peers {
			peers++

			if peer.SSHEnabled {
				peersSSHEnabled++
			}

			if peer.SetupKey == "" {
				userPeers++
			}

			osKey := strings.ToLower(fmt.Sprintf("peer_os_%s", peer.Meta.GoOS))
			osCount := osPeers[osKey]
			osPeers[osKey] = osCount + 1

			if peer.Meta.UIVersion != "" {
				uiClient++
				uiOSKey := strings.ToLower(fmt.Sprintf("ui_client_os_%s", peer.Meta.GoOS))
				osUICount := osUIClients[uiOSKey]
				osUIClients[uiOSKey] = osUICount + 1
			}

			_, connected := connections[peer.ID]
			if connected || peer.Status.LastSeen.After(w.lastRun) {
				activePeersLastDay++
				osActiveKey := osKey + "_active"
				osActiveCount := osPeers[osActiveKey]
				osPeers[osActiveKey] = osActiveCount + 1
				peerActiveVersions = append(peerActiveVersions, peer.Meta.WtVersion)
			}
		}
	}

	minActivePeerVersion, maxActivePeerVersion := getMinMaxVersion(peerActiveVersions)
	metricsProperties["uptime"] = uptime
	metricsProperties["accounts"] = accounts
	metricsProperties["users"] = users
	metricsProperties["service_users"] = serviceUsers
	metricsProperties["pats"] = pats
	metricsProperties["peers"] = peers
	metricsProperties["peers_ssh_enabled"] = peersSSHEnabled
	metricsProperties["peers_login_expiration_enabled"] = expirationEnabled
	metricsProperties["setup_keys_usage"] = setupKeysUsage
	metricsProperties["active_peers_last_day"] = activePeersLastDay
	metricsProperties["user_peers"] = userPeers
	metricsProperties["rules"] = rules
	metricsProperties["rules_protocol"] = rulesProtocol
	metricsProperties["rules_direction"] = rulesDirection
	metricsProperties["groups"] = groups
	metricsProperties["routes"] = routes
	metricsProperties["nameservers"] = nameservers
	metricsProperties["version"] = version
	metricsProperties["min_active_peer_version"] = minActivePeerVersion
	metricsProperties["max_active_peer_version"] = maxActivePeerVersion
	metricsProperties["ui_clients"] = uiClient
	for os, count := range osPeers {
		metricsProperties[os] = count
	}

	for os, count := range osUIClients {
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

func getMinMaxVersion(inputList []string) (string, string) {
	reg, err := regexp.Compile(version.SemverRegexpRaw)
	if err != nil {
		return "", ""
	}

	versions := make([]*version.Version, 0)

	for _, raw := range inputList {
		if raw != "" && reg.MatchString(raw) {
			v, err := version.NewVersion(raw)
			if err == nil {
				versions = append(versions, v)
			}
		}
	}
	switch len(versions) {
	case 0:
		return "", ""
	case 1:
		v := versions[0].String()
		return v, v
	default:
		sort.Sort(version.Collection(versions))
		return versions[0].String(), versions[len(versions)-1].String()
	}
}
