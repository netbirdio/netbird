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
)

const (
	defaultListenAddr  = ":8087"
	defaultInfluxDBURL = "http://influxdb:8086/api/v2/write?org=netbird&bucket=metrics&precision=ns"
	maxBodySize        = 1 * 1024 * 1024 // 1 MB max request body
	maxTotalSeconds    = 300.0           // reject total_seconds > 5 minutes
	peerIDLength       = 16              // truncated SHA-256: 8 bytes = 16 hex chars
)

var allowedMeasurements = map[string]map[string]bool{
	"netbird_peer_connection": {
		"signaling_to_connection_seconds":    true,
		"connection_to_wg_handshake_seconds": true,
		"total_seconds":                      true,
	},
	"netbird_sync": {
		"duration_seconds": true,
	},
}

func main() {
	listenAddr := envOr("INGEST_LISTEN_ADDR", defaultListenAddr)
	influxURL := envOr("INFLUXDB_URL", defaultInfluxDBURL)
	influxToken := os.Getenv("INFLUXDB_TOKEN")

	if influxToken == "" {
		log.Fatal("INFLUXDB_TOKEN is required")
	}

	client := &http.Client{Timeout: 10 * 1e9} // 10 seconds

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, influxURL, bytes.NewReader(validated))
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
		defer resp.Body.Close()

		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck
	})

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

// validateAuth checks that the Authorization header contains a valid hashed peer ID.
func validateAuth(r *http.Request) error {
	peerID := r.Header.Get("Authorization")
	if peerID == "" {
		return fmt.Errorf("missing Authorization header")
	}
	if len(peerID) != peerIDLength {
		return fmt.Errorf("invalid Authorization header length")
	}
	if _, err := hex.DecodeString(peerID); err != nil {
		return fmt.Errorf("invalid Authorization header format")
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
		reader = gz
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

	measurement := parts[0]
	if idx := strings.IndexByte(measurement, ','); idx >= 0 {
		measurement = measurement[:idx]
	}

	allowedFields, ok := allowedMeasurements[measurement]
	if !ok {
		return fmt.Errorf("unknown measurement: %q", measurement)
	}

	for _, pair := range strings.Split(parts[1], ",") {
		if err := validateField(pair, measurement, allowedFields); err != nil {
			return err
		}
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
	if fieldName == "total_seconds" && val > maxTotalSeconds {
		return fmt.Errorf("total_seconds too large: %g > %g", val, maxTotalSeconds)
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
