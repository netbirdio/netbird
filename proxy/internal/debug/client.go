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
	defer resp.Body.Close()

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

