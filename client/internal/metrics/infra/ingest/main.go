package main

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultListenAddr  = ":8087"
	defaultInfluxDBURL = "http://influxdb:8086/api/v2/write?org=netbird&bucket=metrics&precision=ns"
	maxBodySize        = 50 * 1024 * 1024 // 50 MB max request body
	maxDurationSeconds = 300.0            // reject any duration field > 5 minutes
	peerIDLength       = 16               // truncated SHA-256: 8 bytes = 16 hex chars
	maxTagValueLength  = 64               // reject tag values longer than this
)

type measurementSpec struct {
	allowedFields map[string]bool
	allowedTags   map[string]bool
}

var allowedMeasurements = map[string]measurementSpec{
	"netbird_peer_connection": {
		allowedFields: map[string]bool{
			"signaling_to_connection_seconds":    true,
			"connection_to_wg_handshake_seconds": true,
			"total_seconds":                      true,
		},
		allowedTags: map[string]bool{
			"deployment_type":    true,
			"connection_type":    true,
			"attempt_type":       true,
			"version":            true,
			"os":                 true,
			"arch":               true,
			"peer_id":            true,
			"connection_pair_id": true,
		},
	},
	"netbird_sync": {
		allowedFields: map[string]bool{
			"duration_seconds": true,
		},
		allowedTags: map[string]bool{
			"deployment_type": true,
			"version":         true,
			"os":              true,
			"arch":            true,
			"peer_id":         true,
		},
	},
	"netbird_login": {
		allowedFields: map[string]bool{
			"duration_seconds": true,
		},
		allowedTags: map[string]bool{
			"deployment_type": true,
			"result":          true,
			"version":         true,
			"os":              true,
			"arch":            true,
			"peer_id":         true,
		},
	},
}

func main() {
	listenAddr := envOr("INGEST_LISTEN_ADDR", defaultListenAddr)
	influxURL := envOr("INFLUXDB_URL", defaultInfluxDBURL)
	influxToken := os.Getenv("INFLUXDB_TOKEN")

	if influxToken == "" {
		log.Fatal("INFLUXDB_TOKEN is required")
	}

	client := &http.Client{Timeout: 10 * time.Second}

	http.HandleFunc("/", handleIngest(client, influxURL, influxToken))

	// Build config JSON once at startup from env vars
	configJSON := buildConfigJSON()
	if configJSON != nil {
		log.Printf("serving remote config at /config")
	}

	http.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if configJSON == nil {
			http.Error(w, "config not configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(configJSON) //nolint:errcheck
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok") //nolint:errcheck
	})

	log.Printf("ingest server listening on %s, forwarding to %s", listenAddr, influxURL)
	if err := http.ListenAndServe(listenAddr, nil); err != nil { //nolint:gosec
		log.Fatal(err)
	}
}

func handleIngest(client *http.Client, influxURL, influxToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := validateAuth(r); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		body, err := readBody(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(body) > maxBodySize {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}

		validated, err := validateLineProtocol(body)
		if err != nil {
			log.Printf("WARN validation failed from %s: %v", r.RemoteAddr, err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		forwardToInflux(w, r, client, influxURL, influxToken, validated)
	}
}

func forwardToInflux(w http.ResponseWriter, r *http.Request, client *http.Client, influxURL, influxToken string, body []byte) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, influxURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("ERROR create request: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Authorization", "Token "+influxToken)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ERROR forward to influxdb: %v", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

// validateAuth checks that the X-Peer-ID header contains a valid hashed peer ID.
func validateAuth(r *http.Request) error {
	peerID := r.Header.Get("X-Peer-ID")
	if peerID == "" {
		return fmt.Errorf("missing X-Peer-ID header")
	}
	if len(peerID) != peerIDLength {
		return fmt.Errorf("invalid X-Peer-ID header length")
	}
	if _, err := hex.DecodeString(peerID); err != nil {
		return fmt.Errorf("invalid X-Peer-ID header format")
	}
	return nil
}

// readBody reads the request body, decompressing gzip if Content-Encoding indicates it.
func readBody(r *http.Request) ([]byte, error) {
	reader := io.LimitReader(r.Body, maxBodySize+1)

	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("invalid gzip: %w", err)
		}
		defer gz.Close()
		reader = io.LimitReader(gz, maxBodySize+1)
	}

	return io.ReadAll(reader)
}

// validateLineProtocol parses InfluxDB line protocol lines,
// whitelists measurements and fields, and checks value bounds.
func validateLineProtocol(body []byte) ([]byte, error) {
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	var valid []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if err := validateLine(line); err != nil {
			return nil, err
		}

		valid = append(valid, line)
	}

	if len(valid) == 0 {
		return nil, fmt.Errorf("no valid lines")
	}

	return []byte(strings.Join(valid, "\n") + "\n"), nil
}

func validateLine(line string) error {
	// line protocol: measurement,tag=val,tag=val field=val,field=val timestamp
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return fmt.Errorf("invalid line protocol: %q", truncate(line, 100))
	}

	// parts[0] is "measurement,tag=val,tag=val"
	measurementAndTags := strings.Split(parts[0], ",")
	measurement := measurementAndTags[0]

	spec, ok := allowedMeasurements[measurement]
	if !ok {
		return fmt.Errorf("unknown measurement: %q", measurement)
	}

	// Validate tags (everything after measurement name in parts[0])
	for _, tagPair := range measurementAndTags[1:] {
		if err := validateTag(tagPair, measurement, spec.allowedTags); err != nil {
			return err
		}
	}

	// Validate fields
	for _, pair := range strings.Split(parts[1], ",") {
		if err := validateField(pair, measurement, spec.allowedFields); err != nil {
			return err
		}
	}

	return nil
}

func validateTag(pair, measurement string, allowedTags map[string]bool) error {
	kv := strings.SplitN(pair, "=", 2)
	if len(kv) != 2 {
		return fmt.Errorf("invalid tag: %q", pair)
	}

	tagName := kv[0]
	if !allowedTags[tagName] {
		return fmt.Errorf("unknown tag %q in measurement %q", tagName, measurement)
	}

	if len(kv[1]) > maxTagValueLength {
		return fmt.Errorf("tag value too long for %q: %d > %d", tagName, len(kv[1]), maxTagValueLength)
	}

	return nil
}

func validateField(pair, measurement string, allowedFields map[string]bool) error {
	kv := strings.SplitN(pair, "=", 2)
	if len(kv) != 2 {
		return fmt.Errorf("invalid field: %q", pair)
	}

	fieldName := kv[0]
	if !allowedFields[fieldName] {
		return fmt.Errorf("unknown field %q in measurement %q", fieldName, measurement)
	}

	val, err := strconv.ParseFloat(kv[1], 64)
	if err != nil {
		return fmt.Errorf("invalid field value %q for %q", kv[1], fieldName)
	}
	if val < 0 {
		return fmt.Errorf("negative value for %q: %g", fieldName, val)
	}
	if strings.HasSuffix(fieldName, "_seconds") && val > maxDurationSeconds {
		return fmt.Errorf("%q too large: %g > %g", fieldName, val, maxDurationSeconds)
	}

	return nil
}

// buildConfigJSON builds the remote config JSON from env vars.
// Returns nil if required vars are not set.
func buildConfigJSON() []byte {
	serverURL := os.Getenv("CONFIG_METRICS_SERVER_URL")
	versionSince := envOr("CONFIG_VERSION_SINCE", "0.0.0")
	versionUntil := envOr("CONFIG_VERSION_UNTIL", "99.99.99")
	periodMinutes := envOr("CONFIG_PERIOD_MINUTES", "5")

	if serverURL == "" {
		return nil
	}

	period, err := strconv.Atoi(periodMinutes)
	if err != nil || period <= 0 {
		log.Printf("WARN invalid CONFIG_PERIOD_MINUTES: %q, using 5", periodMinutes)
		period = 5
	}

	cfg := map[string]any{
		"server_url":     serverURL,
		"version-since":  versionSince,
		"version-until":  versionUntil,
		"period_minutes": period,
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		log.Printf("ERROR failed to marshal config: %v", err)
		return nil
	}
	return data
}

func envOr(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
