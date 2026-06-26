// Package debug provides HTTP debug endpoints for the proxy server.
package debug

import (
	"cmp"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"maps"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	nbembed "github.com/netbirdio/netbird/client/embed"
	nbstatus "github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/proxy/internal/health"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/version"
)

//go:embed templates/*.html
var templateFS embed.FS

const defaultPingTimeout = 10 * time.Second

// formatDuration formats a duration with 2 decimal places using appropriate units.
func formatDuration(d time.Duration) string {
	switch {
	case d >= time.Hour:
		return fmt.Sprintf("%.2fh", d.Hours())
	case d >= time.Minute:
		return fmt.Sprintf("%.2fm", d.Minutes())
	case d >= time.Second:
		return fmt.Sprintf("%.2fs", d.Seconds())
	case d >= time.Millisecond:
		return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000)
	case d >= time.Microsecond:
		return fmt.Sprintf("%.2fµs", float64(d.Nanoseconds())/1000)
	default:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
}

func sortedAccountIDs(m map[types.AccountID]roundtrip.ClientDebugInfo) []types.AccountID {
	return slices.Sorted(maps.Keys(m))
}

// clientProvider provides access to NetBird clients.
type clientProvider interface {
	GetClient(accountID types.AccountID) (*nbembed.Client, bool)
	ListClientsForDebug() map[types.AccountID]roundtrip.ClientDebugInfo
	ListClientsForStartup() map[types.AccountID]*nbembed.Client
}

// InboundListenerInfo describes a per-account inbound listener as
// surfaced through the debug HTTP handler. Mirrors the proto sub-message
// emitted with SendStatusUpdate so dashboards and CLI tooling see the
// same shape.
type InboundListenerInfo struct {
	TunnelIP  string `json:"tunnel_ip"`
	HTTPSPort uint16 `json:"https_port"`
	HTTPPort  uint16 `json:"http_port"`
}

// InboundProvider exposes per-account inbound listener state. Optional;
// when nil the debug endpoint omits the inbound section entirely so the
// existing JSON shape stays additive.
type InboundProvider interface {
	InboundListeners() map[types.AccountID]InboundListenerInfo
}

// healthChecker provides health probe state.
type healthChecker interface {
	ReadinessProbe() bool
	StartupProbe(ctx context.Context) bool
	CheckClientsConnected(ctx context.Context) (bool, map[types.AccountID]health.ClientHealth)
}

type certStatus interface {
	TotalDomains() int
	PendingDomains() []string
	ReadyDomains() []string
	FailedDomains() map[string]string
}

// Handler provides HTTP debug endpoints.
type Handler struct {
	provider   clientProvider
	health     healthChecker
	certStatus certStatus
	inbound    InboundProvider
	logger     *log.Logger
	startTime  time.Time
	templates  *template.Template
	templateMu sync.RWMutex
}

// NewHandler creates a new debug handler.
func NewHandler(provider clientProvider, healthChecker healthChecker, logger *log.Logger) *Handler {
	if logger == nil {
		logger = log.StandardLogger()
	}
	h := &Handler{
		provider:  provider,
		health:    healthChecker,
		logger:    logger,
		startTime: time.Now(),
	}
	if err := h.loadTemplates(); err != nil {
		logger.Errorf("failed to load embedded templates: %v", err)
	}
	return h
}

// SetCertStatus sets the certificate status provider for ACME prefetch observability.
func (h *Handler) SetCertStatus(cs certStatus) {
	h.certStatus = cs
}

// SetInboundProvider wires per-account inbound listener observability.
// Pass nil (or skip the call) to keep the inbound section out of debug
// responses on proxies that don't run --private.
func (h *Handler) SetInboundProvider(p InboundProvider) {
	h.inbound = p
}

func (h *Handler) loadTemplates() error {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return fmt.Errorf("parse embedded templates: %w", err)
	}

	h.templateMu.Lock()
	h.templates = tmpl
	h.templateMu.Unlock()

	return nil
}

func (h *Handler) getTemplates() *template.Template {
	h.templateMu.RLock()
	defer h.templateMu.RUnlock()
	return h.templates
}

// ServeHTTP handles debug requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	wantJSON := r.URL.Query().Get("format") == "json" || strings.HasSuffix(path, "/json")
	path = strings.TrimSuffix(path, "/json")

	switch path {
	case "/debug", "/debug/":
		h.handleIndex(w, r, wantJSON)
	case "/debug/clients":
		h.handleListClients(w, r, wantJSON)
	case "/debug/health":
		h.handleHealth(w, r, wantJSON)
	case "/debug/perf":
		h.handlePerf(w, r)
	case "/debug/runtime":
		h.handleRuntime(w, r)
	default:
		if h.handleClientRoutes(w, r, path, wantJSON) {
			return
		}
		http.NotFound(w, r)
	}
}

func (h *Handler) handleClientRoutes(w http.ResponseWriter, r *http.Request, path string, wantJSON bool) bool {
	if !strings.HasPrefix(path, "/debug/clients/") {
		return false
	}

	rest := strings.TrimPrefix(path, "/debug/clients/")
	parts := strings.SplitN(rest, "/", 2)
	accountID := types.AccountID(parts[0])

	if len(parts) == 1 {
		h.handleClientStatus(w, r, accountID, wantJSON)
		return true
	}

	switch parts[1] {
	case "syncresponse":
		h.handleClientSyncResponse(w, r, accountID, wantJSON)
	case "tools":
		h.handleClientTools(w, r, accountID)
	case "pingtcp":
		h.handlePingTCP(w, r, accountID)
	case "loglevel":
		h.handleLogLevel(w, r, accountID)
	case "start":
		h.handleClientStart(w, r, accountID)
	case "stop":
		h.handleClientStop(w, r, accountID)
	case "capture":
		h.handleCapture(w, r, accountID)
	default:
		return false
	}
	return true
}

type failedDomain struct {
	Domain string
	Error  string
}

type indexData struct {
	Version             string
	Uptime              string
	ClientCount         int
	TotalServices       int
	CertsTotal          int
	CertsReady          int
	CertsPending        int
	CertsFailed         int
	CertsPendingDomains []string
	CertsReadyDomains   []string
	CertsFailedDomains  []failedDomain
	Clients             []clientData
}

type clientData struct {
	AccountID string
	Services  string
	Age       string
	Status    string
}

func (h *Handler) handleIndex(w http.ResponseWriter, _ *http.Request, wantJSON bool) {
	clients := h.provider.ListClientsForDebug()
	sortedIDs := sortedAccountIDs(clients)

	totalServices := 0
	for _, info := range clients {
		totalServices += info.ServiceCount
	}

	var certsTotal, certsReady, certsPending, certsFailed int
	var certsPendingDomains, certsReadyDomains []string
	var certsFailedDomains map[string]string
	if h.certStatus != nil {
		certsTotal = h.certStatus.TotalDomains()
		certsPendingDomains = h.certStatus.PendingDomains()
		certsReadyDomains = h.certStatus.ReadyDomains()
		certsFailedDomains = h.certStatus.FailedDomains()
		certsReady = len(certsReadyDomains)
		certsPending = len(certsPendingDomains)
		certsFailed = len(certsFailedDomains)
	}

	if wantJSON {
		clientsJSON := make([]map[string]any, 0, len(clients))
		for _, id := range sortedIDs {
			info := clients[id]
			clientsJSON = append(clientsJSON, map[string]any{
				"account_id":    info.AccountID,
				"service_count": info.ServiceCount,
				"service_keys":  info.ServiceKeys,
				"has_client":    info.HasClient,
				"created_at":    info.CreatedAt,
				"age":           time.Since(info.CreatedAt).Round(time.Second).String(),
			})
		}
		resp := map[string]any{
			"version":        version.NetbirdVersion(),
			"uptime":         time.Since(h.startTime).Round(time.Second).String(),
			"client_count":   len(clients),
			"total_services": totalServices,
			"certs_total":    certsTotal,
			"certs_ready":    certsReady,
			"certs_pending":  certsPending,
			"certs_failed":   certsFailed,
			"clients":        clientsJSON,
		}
		if len(certsPendingDomains) > 0 {
			resp["certs_pending_domains"] = certsPendingDomains
		}
		if len(certsReadyDomains) > 0 {
			resp["certs_ready_domains"] = certsReadyDomains
		}
		if len(certsFailedDomains) > 0 {
			resp["certs_failed_domains"] = certsFailedDomains
		}
		h.writeJSON(w, resp)
		return
	}

	sortedFailed := make([]failedDomain, 0, len(certsFailedDomains))
	for d, e := range certsFailedDomains {
		sortedFailed = append(sortedFailed, failedDomain{Domain: d, Error: e})
	}
	slices.SortFunc(sortedFailed, func(a, b failedDomain) int {
		return cmp.Compare(a.Domain, b.Domain)
	})

	data := indexData{
		Version:             version.NetbirdVersion(),
		Uptime:              time.Since(h.startTime).Round(time.Second).String(),
		ClientCount:         len(clients),
		TotalServices:       totalServices,
		CertsTotal:          certsTotal,
		CertsReady:          certsReady,
		CertsPending:        certsPending,
		CertsFailed:         certsFailed,
		CertsPendingDomains: certsPendingDomains,
		CertsReadyDomains:   certsReadyDomains,
		CertsFailedDomains:  sortedFailed,
		Clients:             make([]clientData, 0, len(clients)),
	}

	for _, id := range sortedIDs {
		info := clients[id]
		services := strings.Join(info.ServiceKeys, ", ")
		if services == "" {
			services = "-"
		}
		status := "No client"
		if info.HasClient {
			status = "Active"
		}
		data.Clients = append(data.Clients, clientData{
			AccountID: string(info.AccountID),
			Services:  services,
			Age:       time.Since(info.CreatedAt).Round(time.Second).String(),
			Status:    status,
		})
	}

	h.renderTemplate(w, "index", data)
}

type clientsData struct {
	Uptime  string
	Clients []clientData
}

func (h *Handler) handleListClients(w http.ResponseWriter, _ *http.Request, wantJSON bool) {
	clients := h.provider.ListClientsForDebug()
	sortedIDs := sortedAccountIDs(clients)

	if wantJSON {
		var inboundAll map[types.AccountID]InboundListenerInfo
		if h.inbound != nil {
			inboundAll = h.inbound.InboundListeners()
		}
		clientsJSON := make([]map[string]any, 0, len(clients))
		for _, id := range sortedIDs {
			info := clients[id]
			row := map[string]any{
				"account_id":    info.AccountID,
				"service_count": info.ServiceCount,
				"service_keys":  info.ServiceKeys,
				"has_client":    info.HasClient,
				"created_at":    info.CreatedAt,
				"age":           time.Since(info.CreatedAt).Round(time.Second).String(),
			}
			if inb, ok := inboundAll[id]; ok {
				row["inbound_listener"] = inb
			}
			clientsJSON = append(clientsJSON, row)
		}
		resp := map[string]any{
			"uptime":       time.Since(h.startTime).Round(time.Second).String(),
			"client_count": len(clients),
			"clients":      clientsJSON,
		}
		if len(inboundAll) > 0 {
			resp["inbound_listener_count"] = len(inboundAll)
		}
		h.writeJSON(w, resp)
		return
	}

	data := clientsData{
		Uptime:  time.Since(h.startTime).Round(time.Second).String(),
		Clients: make([]clientData, 0, len(clients)),
	}

	for _, id := range sortedIDs {
		info := clients[id]
		services := strings.Join(info.ServiceKeys, ", ")
		if services == "" {
			services = "-"
		}
		status := "No client"
		if info.HasClient {
			status = "Active"
		}
		data.Clients = append(data.Clients, clientData{
			AccountID: string(info.AccountID),
			Services:  services,
			Age:       time.Since(info.CreatedAt).Round(time.Second).String(),
			Status:    status,
		})
	}

	h.renderTemplate(w, "clients", data)
}

type clientDetailData struct {
	AccountID string
	ActiveTab string
	Content   string
}

func (h *Handler) handleClientStatus(w http.ResponseWriter, r *http.Request, accountID types.AccountID, wantJSON bool) {
	client, ok := h.provider.GetClient(accountID)
	if !ok {
		http.Error(w, "Client not found: "+string(accountID), http.StatusNotFound)
		return
	}

	fullStatus, err := client.Status()
	if err != nil {
		http.Error(w, "Error getting status: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse filter parameters
	query := r.URL.Query()
	statusFilter := query.Get("filter-by-status")
	connectionTypeFilter := query.Get("filter-by-connection-type")

	var prefixNamesFilter []string
	var prefixNamesFilterMap map[string]struct{}
	if names := query.Get("filter-by-names"); names != "" {
		prefixNamesFilter = strings.Split(names, ",")
		prefixNamesFilterMap = make(map[string]struct{})
		for _, name := range prefixNamesFilter {
			prefixNamesFilterMap[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
		}
	}

	var ipsFilterMap map[string]struct{}
	if ips := query.Get("filter-by-ips"); ips != "" {
		ipsFilterMap = make(map[string]struct{})
		for _, ip := range strings.Split(ips, ",") {
			ipsFilterMap[strings.TrimSpace(ip)] = struct{}{}
		}
	}

	pbStatus := nbstatus.ToProtoFullStatus(fullStatus)
	overview := nbstatus.ConvertToStatusOutputOverview(pbStatus, nbstatus.ConvertOptions{
		StatusFilter:         statusFilter,
		PrefixNamesFilter:    prefixNamesFilter,
		PrefixNamesFilterMap: prefixNamesFilterMap,
		IPsFilter:            ipsFilterMap,
		ConnectionTypeFilter: connectionTypeFilter,
	})

	if wantJSON {
		resp := map[string]any{
			"account_id": accountID,
			"status":     overview.FullDetailSummary(),
		}
		if info, ok := h.inboundInfoFor(accountID); ok {
			resp["inbound_listener"] = info
		}
		h.writeJSON(w, resp)
		return
	}

	data := clientDetailData{
		AccountID: string(accountID),
		ActiveTab: "status",
		Content:   overview.FullDetailSummary(),
	}

	h.renderTemplate(w, "clientDetail", data)
}

// inboundInfoFor returns the inbound listener info for an account, or
// ok=false when no inbound provider is wired or the account has no live
// listener.
func (h *Handler) inboundInfoFor(accountID types.AccountID) (InboundListenerInfo, bool) {
	if h.inbound == nil {
		return InboundListenerInfo{}, false
	}
	all := h.inbound.InboundListeners()
	info, ok := all[accountID]
	return info, ok
}

func (h *Handler) handleClientSyncResponse(w http.ResponseWriter, _ *http.Request, accountID types.AccountID, wantJSON bool) {
	client, ok := h.provider.GetClient(accountID)
	if !ok {
		http.Error(w, "Client not found: "+string(accountID), http.StatusNotFound)
		return
	}

	syncResp, err := client.GetLatestSyncResponse()
	if err != nil {
		http.Error(w, "Error getting sync response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if syncResp == nil {
		http.Error(w, "No sync response available for client: "+string(accountID), http.StatusNotFound)
		return
	}

	opts := protojson.MarshalOptions{
		EmitUnpopulated: true,
		UseProtoNames:   true,
		Indent:          "  ",
		AllowPartial:    true,
	}

	jsonBytes, err := opts.Marshal(syncResp)
	if err != nil {
		http.Error(w, "Error marshaling sync response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if wantJSON {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonBytes)
		return
	}

	data := clientDetailData{
		AccountID: string(accountID),
		ActiveTab: "syncresponse",
		Content:   string(jsonBytes),
	}

	h.renderTemplate(w, "clientDetail", data)
}

type toolsData struct {
	AccountID string
}

func (h *Handler) handleClientTools(w http.ResponseWriter, _ *http.Request, accountID types.AccountID) {
	_, ok := h.provider.GetClient(accountID)
	if !ok {
		http.Error(w, "Client not found: "+string(accountID), http.StatusNotFound)
		return
	}

	data := toolsData{
		AccountID: string(accountID),
	}

	h.renderTemplate(w, "tools", data)
}

func (h *Handler) handlePingTCP(w http.ResponseWriter, r *http.Request, accountID types.AccountID) {
	client, ok := h.provider.GetClient(accountID)
	if !ok {
		h.writeJSON(w, map[string]any{"error": "client not found"})
		return
	}

	host := r.URL.Query().Get("host")
	portStr := r.URL.Query().Get("port")
	if host == "" || portStr == "" {
		h.writeJSON(w, map[string]any{"error": "host and port parameters required"})
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		h.writeJSON(w, map[string]any{"error": "invalid port"})
		return
	}

	timeout := defaultPingTimeout
	if t := r.URL.Query().Get("timeout"); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			timeout = d
		}
	}

	network := "tcp"
	if v := r.URL.Query().Get("ip_version"); v == "4" || v == "6" {
		network += v
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	address := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()

	conn, err := client.Dial(ctx, network, address)
	if err != nil {
		h.writeJSON(w, map[string]any{
			"success": false,
			"host":    host,
			"port":    port,
			"error":   err.Error(),
		})
		return
	}

	remote := conn.RemoteAddr().String()
	if err := conn.Close(); err != nil {
		h.logger.Debugf("close tcp ping connection: %v", err)
	}

	latency := time.Since(start)
	h.writeJSON(w, map[string]any{
		"success":    true,
		"host":       host,
		"port":       port,
		"remote":     remote,
		"latency_ms": latency.Milliseconds(),
		"latency":    formatDuration(latency),
	})
}

func (h *Handler) handleLogLevel(w http.ResponseWriter, r *http.Request, accountID types.AccountID) {
	client, ok := h.provider.GetClient(accountID)
	if !ok {
		h.writeJSON(w, map[string]any{"error": "client not found"})
		return
	}

	level := r.URL.Query().Get("level")
	if level == "" {
		h.writeJSON(w, map[string]any{"error": "level parameter required (trace, debug, info, warn, error)"})
		return
	}

	if err := client.SetLogLevel(level); err != nil {
		h.writeJSON(w, map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	h.writeJSON(w, map[string]any{
		"success": true,
		"level":   level,
	})
}

const clientActionTimeout = 30 * time.Second

func (h *Handler) handleClientStart(w http.ResponseWriter, r *http.Request, accountID types.AccountID) {
	client, ok := h.provider.GetClient(accountID)
	if !ok {
		h.writeJSON(w, map[string]any{"error": "client not found"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), clientActionTimeout)
	defer cancel()

	if err := client.Start(ctx); err != nil {
		h.writeJSON(w, map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	h.writeJSON(w, map[string]any{
		"success": true,
		"message": "client started",
	})
}

func (h *Handler) handleClientStop(w http.ResponseWriter, r *http.Request, accountID types.AccountID) {
	client, ok := h.provider.GetClient(accountID)
	if !ok {
		h.writeJSON(w, map[string]any{"error": "client not found"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), clientActionTimeout)
	defer cancel()

	if err := client.Stop(ctx); err != nil {
		h.writeJSON(w, map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	h.writeJSON(w, map[string]any{
		"success": true,
		"message": "client stopped",
	})
}

func (h *Handler) handlePerf(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("value")
	if raw == "" {
		http.Error(w, "value parameter is required", http.StatusBadRequest)
		return
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid value %q: %v", raw, err), http.StatusBadRequest)
		return
	}

	capN := uint32(n)
	applied := 0
	failed := map[string]string{}
	for accountID, client := range h.provider.ListClientsForStartup() {
		if err := client.SetPerformance(nbembed.Performance{PreallocatedBuffersPerPool: &capN}); err != nil {
			failed[string(accountID)] = err.Error()
			continue
		}
		applied++
	}

	resp := map[string]any{
		"success": true,
		"value":   capN,
		"applied": applied,
	}
	if len(failed) > 0 {
		resp["failed"] = failed
	}
	h.writeJSON(w, resp)
}

// handleRuntime returns cheap runtime and process stats. Safe to hit on a
// running proxy; does not read pprof profiles.
func (h *Handler) handleRuntime(w http.ResponseWriter, _ *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	clients := h.provider.ListClientsForDebug()
	started := 0
	for _, c := range clients {
		if c.HasClient {
			started++
		}
	}

	resp := map[string]any{
		"uptime":         time.Since(h.startTime).Round(time.Second).String(),
		"goroutines":     runtime.NumGoroutine(),
		"num_cpu":        runtime.NumCPU(),
		"gomaxprocs":     runtime.GOMAXPROCS(0),
		"go_version":     runtime.Version(),
		"heap_alloc":     m.HeapAlloc,
		"heap_inuse":     m.HeapInuse,
		"heap_idle":      m.HeapIdle,
		"heap_released":  m.HeapReleased,
		"heap_sys":       m.HeapSys,
		"sys":            m.Sys,
		"live_objects":   m.Mallocs - m.Frees,
		"num_gc":         m.NumGC,
		"pause_total_ns": m.PauseTotalNs,
		"clients":        len(clients),
		"started":        started,
	}

	if proc := readProcStatus(); proc != nil {
		resp["vm_rss"] = proc["VmRSS"]
		resp["vm_size"] = proc["VmSize"]
		resp["vm_data"] = proc["VmData"]
	}

	h.writeJSON(w, resp)
}

// readProcStatus parses /proc/self/status on Linux and returns size fields
// in bytes. Returns nil on non-Linux or read failure.
func readProcStatus() map[string]uint64 {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil
	}
	out := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if k != "VmRSS" && k != "VmSize" && k != "VmData" {
			continue
		}
		fields := strings.Fields(v)
		if len(fields) < 1 {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		// Values are reported in kB.
		out[k] = n * 1024
	}
	return out
}

const maxCaptureDuration = 30 * time.Minute

// handleCapture streams a pcap or text packet capture for the given client.
//
// Query params:
//
//	duration: capture duration (0 or absent = max, capped at 30m)
//	format:   "text" for human-readable output (default: pcap)
//	filter:   BPF-like filter expression (e.g. "host 10.0.0.1 and tcp port 443")
func (h *Handler) handleCapture(w http.ResponseWriter, r *http.Request, accountID types.AccountID) {
	client, ok := h.provider.GetClient(accountID)
	if !ok {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	duration := maxCaptureDuration
	if durationStr := r.URL.Query().Get("duration"); durationStr != "" {
		d, err := time.ParseDuration(durationStr)
		if err != nil {
			http.Error(w, "invalid duration: "+err.Error(), http.StatusBadRequest)
			return
		}
		if d < 0 {
			http.Error(w, "duration must not be negative", http.StatusBadRequest)
			return
		}
		if d > 0 {
			duration = min(d, maxCaptureDuration)
		}
	}

	filter := r.URL.Query().Get("filter")
	wantText := r.URL.Query().Get("format") == "text"
	verbose := r.URL.Query().Get("verbose") == "true"
	ascii := r.URL.Query().Get("ascii") == "true"

	opts := nbembed.CaptureOptions{Filter: filter, Verbose: verbose, ASCII: ascii}
	if wantText {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		opts.TextOutput = w
	} else {
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=capture-%s.pcap", accountID))
		opts.Output = w
	}

	cs, err := client.StartCapture(opts)
	if err != nil {
		http.Error(w, "start capture: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer cs.Stop()

	// Flush headers after setup succeeds so errors above can still set status codes.
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-r.Context().Done():
	case <-timer.C:
	}

	cs.Stop()

	stats := cs.Stats()
	h.logger.Infof("capture for %s finished: %d packets, %d bytes, %d dropped",
		accountID, stats.Packets, stats.Bytes, stats.Dropped)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request, wantJSON bool) {
	if !wantJSON {
		http.Redirect(w, r, "/debug", http.StatusSeeOther)
		return
	}

	uptime := time.Since(h.startTime).Round(10 * time.Millisecond).String()

	ready := h.health.ReadinessProbe()
	allHealthy, clientHealth := h.health.CheckClientsConnected(r.Context())

	status := "ok"
	// No clients is not a health issue; only degrade when actual clients are unhealthy
	if !ready || (!allHealthy && len(clientHealth) > 0) {
		status = "degraded"
	}

	var certsTotal, certsReady, certsPending, certsFailed int
	var certsPendingDomains, certsReadyDomains []string
	var certsFailedDomains map[string]string
	if h.certStatus != nil {
		certsTotal = h.certStatus.TotalDomains()
		certsPendingDomains = h.certStatus.PendingDomains()
		certsReadyDomains = h.certStatus.ReadyDomains()
		certsFailedDomains = h.certStatus.FailedDomains()
		certsReady = len(certsReadyDomains)
		certsPending = len(certsPendingDomains)
		certsFailed = len(certsFailedDomains)
	}

	resp := map[string]any{
		"status":               status,
		"uptime":               uptime,
		"management_connected": ready,
		"all_clients_healthy":  allHealthy,
		"certs_total":          certsTotal,
		"certs_ready":          certsReady,
		"certs_pending":        certsPending,
		"certs_failed":         certsFailed,
		"clients":              clientHealth,
	}
	if len(certsPendingDomains) > 0 {
		resp["certs_pending_domains"] = certsPendingDomains
	}
	if len(certsReadyDomains) > 0 {
		resp["certs_ready_domains"] = certsReadyDomains
	}
	if len(certsFailedDomains) > 0 {
		resp["certs_failed_domains"] = certsFailedDomains
	}
	h.writeJSON(w, resp)
}

func (h *Handler) renderTemplate(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := h.getTemplates()
	if tmpl == nil {
		http.Error(w, "Templates not loaded", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		h.logger.Errorf("execute template %s: %v", name, err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func (h *Handler) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		h.logger.Errorf("encode JSON response: %v", err)
	}
}
