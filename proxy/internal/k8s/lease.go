// Package k8s provides a lightweight Kubernetes API client for coordination
// Leases. It uses raw HTTP calls against the mounted service account
// credentials, avoiding a dependency on client-go.
package k8s

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	saTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec
	saNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	saCACertPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	leaseAPIPath = "/apis/coordination.k8s.io/v1"
)

// ErrConflict is returned when a Lease update fails due to a
// resourceVersion mismatch (another writer updated the object first).
var ErrConflict = errors.New("conflict: resource version mismatch")

// Lease represents a coordination.k8s.io/v1 Lease object with only the
// fields needed for distributed locking.
type Lease struct {
	APIVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Metadata   LeaseMetadata `json:"metadata"`
	Spec       LeaseSpec     `json:"spec"`
}

// LeaseMetadata holds the standard k8s object metadata fields used by Leases.
type LeaseMetadata struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
}

// LeaseSpec holds the Lease specification fields.
type LeaseSpec struct {
	HolderIdentity       *string    `json:"holderIdentity"`
	LeaseDurationSeconds *int32     `json:"leaseDurationSeconds,omitempty"`
	AcquireTime          *MicroTime `json:"acquireTime"`
	RenewTime            *MicroTime `json:"renewTime"`
}

// MicroTime wraps time.Time with Kubernetes MicroTime JSON formatting.
type MicroTime struct {
	time.Time
}

const microTimeFormat = "2006-01-02T15:04:05.000000Z"

// MarshalJSON implements json.Marshaler with k8s MicroTime format.
func (t *MicroTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.UTC().Format(microTimeFormat))
}

// UnmarshalJSON implements json.Unmarshaler with k8s MicroTime format.
func (t *MicroTime) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		t.Time = time.Time{}
		return nil
	}

	parsed, err := time.Parse(microTimeFormat, s)
	if err != nil {
		return fmt.Errorf("parse MicroTime %q: %w", s, err)
	}
	t.Time = parsed
	return nil
}

// LeaseClient talks to the Kubernetes coordination API using raw HTTP.
type LeaseClient struct {
	baseURL    string
	namespace  string
	httpClient *http.Client
}

// NewLeaseClient creates a client that authenticates via the pod's
// mounted service account. It reads the namespace and CA certificate
// at construction time (they don't rotate) but reads the bearer token
// fresh on each request (tokens rotate).
func NewLeaseClient() (*LeaseClient, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("KUBERNETES_SERVICE_HOST/PORT not set")
	}

	ns, err := os.ReadFile(saNamespacePath)
	if err != nil {
		return nil, fmt.Errorf("read namespace from %s: %w", saNamespacePath, err)
	}

	caCert, err := os.ReadFile(saCACertPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert from %s: %w", saCACertPath, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("parse CA certificate from %s", saCACertPath)
	}

	return &LeaseClient{
		baseURL:   fmt.Sprintf("https://%s:%s", host, port),
		namespace: strings.TrimSpace(string(ns)),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: pool,
				},
			},
		},
	}, nil
}

// Namespace returns the namespace this client operates in.
func (c *LeaseClient) Namespace() string {
	return c.namespace
}

// Get retrieves a Lease by name. Returns (nil, nil) if the Lease does not exist.
func (c *LeaseClient) Get(ctx context.Context, name string) (*Lease, error) {
	url := fmt.Sprintf("%s%s/namespaces/%s/leases/%s", c.baseURL, leaseAPIPath, c.namespace, name)

	resp, err := c.doRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil //nolint:nilnil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	var lease Lease
	if err := json.NewDecoder(resp.Body).Decode(&lease); err != nil {
		return nil, fmt.Errorf("decode lease response: %w", err)
	}
	return &lease, nil
}

// Create creates a new Lease. Returns the created Lease with server-assigned
// fields like resourceVersion populated.
func (c *LeaseClient) Create(ctx context.Context, lease *Lease) (*Lease, error) {
	url := fmt.Sprintf("%s%s/namespaces/%s/leases", c.baseURL, leaseAPIPath, c.namespace)

	lease.APIVersion = "coordination.k8s.io/v1"
	lease.Kind = "Lease"
	if lease.Metadata.Namespace == "" {
		lease.Metadata.Namespace = c.namespace
	}

	resp, err := c.doRequest(ctx, http.MethodPost, url, lease)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusConflict {
		return nil, ErrConflict
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, c.readError(resp)
	}

	var created Lease
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, fmt.Errorf("decode created lease: %w", err)
	}
	return &created, nil
}

// Update replaces a Lease. The lease.Metadata.ResourceVersion must match
// the current server value (optimistic concurrency). Returns ErrConflict
// on version mismatch.
func (c *LeaseClient) Update(ctx context.Context, lease *Lease) (*Lease, error) {
	url := fmt.Sprintf("%s%s/namespaces/%s/leases/%s", c.baseURL, leaseAPIPath, c.namespace, lease.Metadata.Name)

	lease.APIVersion = "coordination.k8s.io/v1"
	lease.Kind = "Lease"

	resp, err := c.doRequest(ctx, http.MethodPut, url, lease)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusConflict {
		return nil, ErrConflict
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	var updated Lease
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		return nil, fmt.Errorf("decode updated lease: %w", err)
	}
	return &updated, nil
}

func (c *LeaseClient) doRequest(ctx context.Context, method, url string, body any) (*http.Response, error) {
	token, err := readToken()
	if err != nil {
		return nil, fmt.Errorf("read service account token: %w", err)
	}

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.httpClient.Do(req)
}

func readToken() (string, error) {
	data, err := os.ReadFile(saTokenPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", saTokenPath, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func (c *LeaseClient) readError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("k8s API %s %d: %s", resp.Request.URL.Path, resp.StatusCode, string(body))
}

// LeaseNameForDomain returns a deterministic, DNS-label-safe Lease name
// for the given domain. The domain is hashed to avoid dots and length issues.
func LeaseNameForDomain(domain string) string {
	h := sha256.Sum256([]byte(domain))
	return "cert-lock-" + hex.EncodeToString(h[:8])
}

// InCluster reports whether the process is running inside a Kubernetes pod
// by checking for the KUBERNETES_SERVICE_HOST environment variable.
func InCluster() bool {
	_, exists := os.LookupEnv("KUBERNETES_SERVICE_HOST")
	return exists
}
