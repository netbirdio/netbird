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
	"net/http"
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
	TotalDomains        int
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
	Domains   string
	Age       string
	Status    string
}

func (h *Handler) handleIndex(w http.ResponseWriter, _ *http.Request, wantJSON bool) {
	clients := h.provider.ListClientsForDebug()
	sortedIDs := sortedAccountIDs(clients)

	totalDomains := 0
	for _, info := range clients {
		totalDomains += info.DomainCount
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
		clientsJSON := make([]map[string]interface{}, 0, len(clients))
		for _, id := range sortedIDs {
			info := clients[id]
			clientsJSON = append(clientsJSON, map[string]interface{}{
				"account_id":   info.AccountID,
				"domain_count": info.DomainCount,
				"domains":      info.Domains,
				"has_client":   info.HasClient,
				"created_at":   info.CreatedAt,
				"age":          time.Since(info.CreatedAt).Round(time.Second).String(),
			})
		}
		resp := map[string]interface{}{
			"version":       version.NetbirdVersion(),
			"uptime":        time.Since(h.startTime).Round(time.Second).String(),
			"client_count":  len(clients),
			"total_domains": totalDomains,
			"certs_total":   certsTotal,
			"certs_ready":   certsReady,
			"certs_pending": certsPending,
			"certs_failed":  certsFailed,
			"clients":       clientsJSON,
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
		TotalDomains:        totalDomains,
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
		domains := info.Domains.SafeString()
		if domains == "" {
			domains = "-"
		}
		status := "No client"
		if info.HasClient {
			status = "Active"
		}
		data.Clients = append(data.Clients, clientData{
			AccountID: string(info.AccountID),
			Domains:   domains,
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
		clientsJSON := make([]map[string]interface{}, 0, len(clients))
		for _, id := range sortedIDs {
			info := clients[id]
			clientsJSON = append(clientsJSON, map[string]interface{}{
				"account_id":   info.AccountID,
				"domain_count": info.DomainCount,
				"domains":      info.Domains,
				"has_client":   info.HasClient,
				"created_at":   info.CreatedAt,
				"age":          time.Since(info.CreatedAt).Round(time.Second).String(),
			})
		}
		h.writeJSON(w, map[string]interface{}{
			"uptime":       time.Since(h.startTime).Round(time.Second).String(),
			"client_count": len(clients),
			"clients":      clientsJSON,
		})
		return
	}

	data := clientsData{
		Uptime:  time.Since(h.startTime).Round(time.Second).String(),
		Clients: make([]clientData, 0, len(clients)),
	}

	for _, id := range sortedIDs {
		info := clients[id]
		domains := info.Domains.SafeString()
		if domains == "" {
			domains = "-"
		}
		status := "No client"
		if info.HasClient {
			status = "Active"
		}
		data.Clients = append(data.Clients, clientData{
			AccountID: string(info.AccountID),
			Domains:   domains,
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
	overview := nbstatus.ConvertToStatusOutputOverview(
		pbStatus,
		false,
		version.NetbirdVersion(),
		statusFilter,
		prefixNamesFilter,
		prefixNamesFilterMap,
		ipsFilterMap,
		connectionTypeFilter,
		"",
	)

	if wantJSON {
		h.writeJSON(w, map[string]interface{}{
			"account_id": accountID,
			"status":     overview.FullDetailSummary(),
		})
		return
	}

	data := clientDetailData{
		AccountID: string(accountID),
		ActiveTab: "status",
		Content:   overview.FullDetailSummary(),
	}

	h.renderTemplate(w, "clientDetail", data)
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
		h.writeJSON(w, map[string]interface{}{"error": "client not found"})
		return
	}

	host := r.URL.Query().Get("host")
	portStr := r.URL.Query().Get("port")
	if host == "" || portStr == "" {
		h.writeJSON(w, map[string]interface{}{"error": "host and port parameters required"})
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		h.writeJSON(w, map[string]interface{}{"error": "invalid port"})
		return
	}

	timeout := defaultPingTimeout
	if t := r.URL.Query().Get("timeout"); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			timeout = d
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	address := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()

	conn, err := client.Dial(ctx, "tcp", address)
	if err != nil {
		h.writeJSON(w, map[string]interface{}{
			"success": false,
			"host":    host,
			"port":    port,
			"error":   err.Error(),
		})
		return
	}
	if err := conn.Close(); err != nil {
		h.logger.Debugf("close tcp ping connection: %v", err)
	}

	latency := time.Since(start)
	h.writeJSON(w, map[string]interface{}{
		"success":    true,
		"host":       host,
		"port":       port,
		"latency_ms": latency.Milliseconds(),
		"latency":    formatDuration(latency),
	})
}

func (h *Handler) handleLogLevel(w http.ResponseWriter, r *http.Request, accountID types.AccountID) {
	client, ok := h.provider.GetClient(accountID)
	if !ok {
		h.writeJSON(w, map[string]interface{}{"error": "client not found"})
		return
	}

	level := r.URL.Query().Get("level")
	if level == "" {
		h.writeJSON(w, map[string]interface{}{"error": "level parameter required (trace, debug, info, warn, error)"})
		return
	}

	if err := client.SetLogLevel(level); err != nil {
		h.writeJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	h.writeJSON(w, map[string]interface{}{
		"success": true,
		"level":   level,
	})
}

const clientActionTimeout = 30 * time.Second

func (h *Handler) handleClientStart(w http.ResponseWriter, r *http.Request, accountID types.AccountID) {
	client, ok := h.provider.GetClient(accountID)
	if !ok {
		h.writeJSON(w, map[string]interface{}{"error": "client not found"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), clientActionTimeout)
	defer cancel()

	if err := client.Start(ctx); err != nil {
		h.writeJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	h.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "client started",
	})
}

func (h *Handler) handleClientStop(w http.ResponseWriter, r *http.Request, accountID types.AccountID) {
	client, ok := h.provider.GetClient(accountID)
	if !ok {
		h.writeJSON(w, map[string]interface{}{"error": "client not found"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), clientActionTimeout)
	defer cancel()

	if err := client.Stop(ctx); err != nil {
		h.writeJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	h.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "client stopped",
	})
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

func (h *Handler) renderTemplate(w http.ResponseWriter, name string, data interface{}) {
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

func (h *Handler) writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		h.logger.Errorf("encode JSON response: %v", err)
	}
}
