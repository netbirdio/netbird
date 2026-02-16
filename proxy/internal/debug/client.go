// Package debug provides HTTP debug endpoints and CLI client for the proxy server.
package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// StatusFilters contains filter options for status queries.
type StatusFilters struct {
	IPs            []string
	Names          []string
	Status         string
	ConnectionType string
}

// Client provides CLI access to debug endpoints.
type Client struct {
	baseURL    string
	jsonOutput bool
	httpClient *http.Client
	out        io.Writer
}

// NewClient creates a new debug client.
func NewClient(baseURL string, jsonOutput bool, out io.Writer) *Client {
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &Client{
		baseURL:    baseURL,
		jsonOutput: jsonOutput,
		out:        out,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Health fetches the health status.
func (c *Client) Health(ctx context.Context) error {
	return c.fetchAndPrint(ctx, "/debug/health", c.printHealth)
}

func (c *Client) printHealth(data map[string]any) {
	_, _ = fmt.Fprintf(c.out, "Status: %v\n", data["status"])
	_, _ = fmt.Fprintf(c.out, "Uptime: %v\n", data["uptime"])
	_, _ = fmt.Fprintf(c.out, "Management Connected: %s\n", boolIcon(data["management_connected"]))
	_, _ = fmt.Fprintf(c.out, "All Clients Healthy:  %s\n", boolIcon(data["all_clients_healthy"]))

	total, _ := data["certs_total"].(float64)
	ready, _ := data["certs_ready"].(float64)
	pending, _ := data["certs_pending"].(float64)
	failed, _ := data["certs_failed"].(float64)
	if total > 0 {
		_, _ = fmt.Fprintf(c.out, "Certificates:         %d ready, %d pending, %d failed (%d total)\n",
			int(ready), int(pending), int(failed), int(total))
	}
	if domains, ok := data["certs_ready_domains"].([]any); ok && len(domains) > 0 {
		_, _ = fmt.Fprintf(c.out, "  Ready:\n")
		for _, d := range domains {
			_, _ = fmt.Fprintf(c.out, "    %v\n", d)
		}
	}
	if domains, ok := data["certs_pending_domains"].([]any); ok && len(domains) > 0 {
		_, _ = fmt.Fprintf(c.out, "  Pending:\n")
		for _, d := range domains {
			_, _ = fmt.Fprintf(c.out, "    %v\n", d)
		}
	}
	if domains, ok := data["certs_failed_domains"].(map[string]any); ok && len(domains) > 0 {
		_, _ = fmt.Fprintf(c.out, "  Failed:\n")
		for d, errMsg := range domains {
			_, _ = fmt.Fprintf(c.out, "    %s: %v\n", d, errMsg)
		}
	}

	c.printHealthClients(data)
}

func (c *Client) printHealthClients(data map[string]any) {
	clients, ok := data["clients"].(map[string]any)
	if !ok || len(clients) == 0 {
		return
	}

	_, _ = fmt.Fprintf(c.out, "\n%-38s %-9s %-7s %-8s %-8s %-16s %s\n",
		"ACCOUNT ID", "HEALTHY", "MGMT", "SIGNAL", "RELAYS", "PEERS (P2P/RLY)", "DEGRADED")
	_, _ = fmt.Fprintln(c.out, strings.Repeat("-", 110))

	for accountID, v := range clients {
		ch, ok := v.(map[string]any)
		if !ok {
			continue
		}

		healthy := boolIcon(ch["healthy"])
		mgmt := boolIcon(ch["management_connected"])
		signal := boolIcon(ch["signal_connected"])

		relaysConn, _ := ch["relays_connected"].(float64)
		relaysTotal, _ := ch["relays_total"].(float64)
		relays := fmt.Sprintf("%d/%d", int(relaysConn), int(relaysTotal))

		peersConnected, _ := ch["peers_connected"].(float64)
		peersTotal, _ := ch["peers_total"].(float64)
		peersP2P, _ := ch["peers_p2p"].(float64)
		peersRelayed, _ := ch["peers_relayed"].(float64)
		peersDegraded, _ := ch["peers_degraded"].(float64)
		peers := fmt.Sprintf("%d/%d (%d/%d)", int(peersConnected), int(peersTotal), int(peersP2P), int(peersRelayed))
		degraded := fmt.Sprintf("%d", int(peersDegraded))

		_, _ = fmt.Fprintf(c.out, "%-38s %-9s %-7s %-8s %-8s %-16s %s", accountID, healthy, mgmt, signal, relays, peers, degraded)
		if errMsg, ok := ch["error"].(string); ok && errMsg != "" {
			_, _ = fmt.Fprintf(c.out, "  (%s)", errMsg)
		}
		_, _ = fmt.Fprintln(c.out)
	}
}

func boolIcon(v any) string {
	b, ok := v.(bool)
	if !ok {
		return "?"
	}
	if b {
		return "yes"
	}
	return "no"
}

// ListClients fetches the list of all clients.
func (c *Client) ListClients(ctx context.Context) error {
	return c.fetchAndPrint(ctx, "/debug/clients", c.printClients)
}

func (c *Client) printClients(data map[string]any) {
	_, _ = fmt.Fprintf(c.out, "Uptime: %v\n", data["uptime"])
	_, _ = fmt.Fprintf(c.out, "Clients: %v\n\n", data["client_count"])

	clients, ok := data["clients"].([]any)
	if !ok || len(clients) == 0 {
		_, _ = fmt.Fprintln(c.out, "No clients connected.")
		return
	}

	_, _ = fmt.Fprintf(c.out, "%-38s %-12s %-40s %s\n", "ACCOUNT ID", "AGE", "DOMAINS", "HAS CLIENT")
	_, _ = fmt.Fprintln(c.out, strings.Repeat("-", 110))

	for _, item := range clients {
		c.printClientRow(item)
	}
}

func (c *Client) printClientRow(item any) {
	client, ok := item.(map[string]any)
	if !ok {
		return
	}

	domains := c.extractDomains(client)
	hasClient := "no"
	if hc, ok := client["has_client"].(bool); ok && hc {
		hasClient = "yes"
	}

	_, _ = fmt.Fprintf(c.out, "%-38s %-12v %s %s\n",
		client["account_id"],
		client["age"],
		domains,
		hasClient,
	)
}

func (c *Client) extractDomains(client map[string]any) string {
	d, ok := client["domains"].([]any)
	if !ok || len(d) == 0 {
		return "-"
	}

	parts := make([]string, len(d))
	for i, domain := range d {
		parts[i] = fmt.Sprint(domain)
	}
	return strings.Join(parts, ", ")
}

// ClientStatus fetches the status of a specific client.
func (c *Client) ClientStatus(ctx context.Context, accountID string, filters StatusFilters) error {
	params := url.Values{}
	if len(filters.IPs) > 0 {
		params.Set("filter-by-ips", strings.Join(filters.IPs, ","))
	}
	if len(filters.Names) > 0 {
		params.Set("filter-by-names", strings.Join(filters.Names, ","))
	}
	if filters.Status != "" {
		params.Set("filter-by-status", filters.Status)
	}
	if filters.ConnectionType != "" {
		params.Set("filter-by-connection-type", filters.ConnectionType)
	}

	path := "/debug/clients/" + url.PathEscape(accountID)
	if len(params) > 0 {
		path += "?" + params.Encode()
	}
	return c.fetchAndPrint(ctx, path, c.printClientStatus)
}

func (c *Client) printClientStatus(data map[string]any) {
	_, _ = fmt.Fprintf(c.out, "Account: %v\n\n", data["account_id"])
	if status, ok := data["status"].(string); ok {
		_, _ = fmt.Fprint(c.out, status)
	}
}

// ClientSyncResponse fetches the sync response of a specific client.
func (c *Client) ClientSyncResponse(ctx context.Context, accountID string) error {
	path := "/debug/clients/" + url.PathEscape(accountID) + "/syncresponse"
	return c.fetchAndPrintJSON(ctx, path)
}

// PingTCP performs a TCP ping through a client.
func (c *Client) PingTCP(ctx context.Context, accountID, host string, port int, timeout string) error {
	params := url.Values{}
	params.Set("host", host)
	params.Set("port", fmt.Sprintf("%d", port))
	if timeout != "" {
		params.Set("timeout", timeout)
	}

	path := fmt.Sprintf("/debug/clients/%s/pingtcp?%s", url.PathEscape(accountID), params.Encode())
	return c.fetchAndPrint(ctx, path, c.printPingResult)
}

func (c *Client) printPingResult(data map[string]any) {
	success, _ := data["success"].(bool)
	if success {
		_, _ = fmt.Fprintf(c.out, "Success: %v:%v\n", data["host"], data["port"])
		_, _ = fmt.Fprintf(c.out, "Latency: %v\n", data["latency"])
	} else {
		_, _ = fmt.Fprintf(c.out, "Failed: %v:%v\n", data["host"], data["port"])
		c.printError(data)
	}
}

// SetLogLevel sets the log level of a specific client.
func (c *Client) SetLogLevel(ctx context.Context, accountID, level string) error {
	params := url.Values{}
	params.Set("level", level)

	path := fmt.Sprintf("/debug/clients/%s/loglevel?%s", url.PathEscape(accountID), params.Encode())
	return c.fetchAndPrint(ctx, path, c.printLogLevelResult)
}

func (c *Client) printLogLevelResult(data map[string]any) {
	success, _ := data["success"].(bool)
	if success {
		_, _ = fmt.Fprintf(c.out, "Log level set to: %v\n", data["level"])
	} else {
		_, _ = fmt.Fprintln(c.out, "Failed to set log level")
		c.printError(data)
	}
}

// StartClient starts a specific client.
func (c *Client) StartClient(ctx context.Context, accountID string) error {
	path := "/debug/clients/" + url.PathEscape(accountID) + "/start"
	return c.fetchAndPrint(ctx, path, c.printStartResult)
}

func (c *Client) printStartResult(data map[string]any) {
	success, _ := data["success"].(bool)
	if success {
		_, _ = fmt.Fprintln(c.out, "Client started")
	} else {
		_, _ = fmt.Fprintln(c.out, "Failed to start client")
		c.printError(data)
	}
}

// StopClient stops a specific client.
func (c *Client) StopClient(ctx context.Context, accountID string) error {
	path := "/debug/clients/" + url.PathEscape(accountID) + "/stop"
	return c.fetchAndPrint(ctx, path, c.printStopResult)
}

func (c *Client) printStopResult(data map[string]any) {
	success, _ := data["success"].(bool)
	if success {
		_, _ = fmt.Fprintln(c.out, "Client stopped")
	} else {
		_, _ = fmt.Fprintln(c.out, "Failed to stop client")
		c.printError(data)
	}
}

func (c *Client) printError(data map[string]any) {
	if errMsg, ok := data["error"].(string); ok {
		_, _ = fmt.Fprintf(c.out, "Error: %s\n", errMsg)
	}
}

func (c *Client) fetchAndPrint(ctx context.Context, path string, printer func(map[string]any)) error {
	data, raw, err := c.fetch(ctx, path)
	if err != nil {
		return err
	}

	if c.jsonOutput {
		return c.writeJSON(data)
	}

	if data != nil {
		printer(data)
		return nil
	}

	_, _ = fmt.Fprintln(c.out, string(raw))
	return nil
}

func (c *Client) fetchAndPrintJSON(ctx context.Context, path string) error {
	data, raw, err := c.fetch(ctx, path)
	if err != nil {
		return err
	}

	if data != nil {
		return c.writeJSON(data)
	}

	_, _ = fmt.Fprintln(c.out, string(raw))
	return nil
}

func (c *Client) writeJSON(data map[string]any) error {
	enc := json.NewEncoder(c.out)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func (c *Client) fetch(ctx context.Context, path string) (map[string]any, []byte, error) {
	fullURL := c.baseURL + path
	if !strings.Contains(path, "format=json") {
		if strings.Contains(path, "?") {
			fullURL += "&format=json"
		} else {
			fullURL += "?format=json"
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, body, nil
	}

	return data, body, nil
}
