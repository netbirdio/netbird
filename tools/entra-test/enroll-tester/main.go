// enroll-tester is a standalone command that simulates a NetBird device
// enrolling via the /join/entra endpoints. It is intended for manual
// verification of the server-side Entra device authentication feature until
// the real NetBird Windows client integration lands (Phase 2 of the plan).
//
// What it does:
//
//  1. Generates a fresh self-signed RSA cert whose Subject CN is the Entra
//     device id you supply. In production this cert would come from
//     Cert:\LocalMachine\My with Issuer containing "MS-Organization-Access".
//  2. Generates a WireGuard-style public key (random 32 bytes, base64).
//  3. GETs /join/entra/challenge, decodes the returned nonce.
//  4. Signs the nonce with the RSA key (RSA-PSS SHA-256).
//  5. POSTs /join/entra/enroll with the cert chain + signed nonce + WG key.
//  6. Prints the response, including the bootstrap token and the auto-groups
//     the server resolved for the device.
//
// The server side must already be configured with an EntraDeviceAuth row
// whose TenantID matches --tenant. See TESTING.md for the full walkthrough.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"
)

type challengeResp struct {
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

type enrollReq struct {
	TenantID       string   `json:"tenant_id"`
	EntraDeviceID  string   `json:"entra_device_id"`
	CertChain      []string `json:"cert_chain"`
	Nonce          string   `json:"nonce"`
	NonceSignature string   `json:"nonce_signature"`
	WGPubKey       string   `json:"wg_pub_key"`
	SSHPubKey      string   `json:"ssh_pub_key,omitempty"`
	Hostname       string   `json:"hostname,omitempty"`
}

type enrollResp struct {
	PeerID                   string   `json:"peer_id"`
	EnrollmentBootstrapToken string   `json:"enrollment_bootstrap_token"`
	ResolvedAutoGroups       []string `json:"resolved_auto_groups"`
	MatchedMappingIDs        []string `json:"matched_mapping_ids"`
	ResolutionMode           string   `json:"resolution_mode"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type testerOpts struct {
	baseURL, tenant, deviceID, hostname string
	insecure, verbose                   bool
}

func main() {
	opts := parseFlags()
	client := buildHTTPClient(opts.insecure)

	key, certB64 := mustMakeCert(opts.deviceID, opts.verbose)
	wgPub := mustMakeWGPubKey()
	challenge := fetchChallenge(client, opts.baseURL, opts.verbose)
	sig := signChallenge(key, challenge.Nonce)

	out := postEnroll(client, opts, certB64, challenge.Nonce, sig, wgPub)
	printEnrolmentSuccess(out, wgPub)
}

// parseFlags parses command-line flags, applies the --demo bootstrap, and
// returns the normalized options.
func parseFlags() testerOpts {
	var (
		baseURL  = flag.String("url", "http://localhost:33081", "Base URL of the management HTTP server (no trailing slash, no /join/entra suffix)")
		tenant   = flag.String("tenant", "", "Entra tenant ID registered on the server (required unless --demo)")
		deviceID = flag.String("device-id", "test-device-0000-0000-0000-000000000001", "Entra device ID. Used as the cert Subject CN.")
		hostname = flag.String("hostname", "", "Hostname to present to the server. Defaults to device-<id>.")
		insecure = flag.Bool("insecure", false, "Skip TLS certificate verification (useful for self-signed dev setups)")
		verbose  = flag.Bool("v", false, "Print request/response bodies")
		demo     = flag.Bool("demo", false, "Run a fully self-contained in-process demo: spins up the real HTTP handler, seeds a wildcard mapping, and enrols against itself. Requires no external server or Entra tenant.")
	)
	flag.Parse()

	if *demo {
		addr, _ := runInProcessServer()
		*baseURL = addr
		if *tenant == "" {
			*tenant = demoTenantID
		}
		fmt.Printf("[demo] in-process server listening on %s\n", addr)
		fmt.Printf("[demo] using tenant %q with wildcard mapping -> [%s]\n\n", *tenant, demoAutoGroup)
	}

	if *tenant == "" {
		fmt.Fprintln(os.Stderr, "error: --tenant is required (or pass --demo for an in-process round-trip)")
		flag.Usage()
		os.Exit(2)
	}
	if *hostname == "" {
		*hostname = "device-" + *deviceID
	}
	return testerOpts{
		baseURL: *baseURL, tenant: *tenant, deviceID: *deviceID,
		hostname: *hostname, insecure: *insecure, verbose: *verbose,
	}
}

func buildHTTPClient(insecure bool) *http.Client {
	c := &http.Client{Timeout: 15 * time.Second}
	if insecure {
		c.Transport = insecureTransport()
	}
	return c
}

func mustMakeCert(deviceID string, verbose bool) (*rsa.PrivateKey, string) {
	key, certB64, err := makeCert(deviceID)
	if err != nil {
		die("generate cert: %v", err)
	}
	if verbose {
		fmt.Printf("Generated self-signed RSA cert for CN=%s (%d chars DER-b64)\n", deviceID, len(certB64))
	}
	return key, certB64
}

func mustMakeWGPubKey() string {
	wgBytes := make([]byte, 32)
	if _, err := rand.Read(wgBytes); err != nil {
		die("generate wg pubkey: %v", err)
	}
	return base64.StdEncoding.EncodeToString(wgBytes)
}

func fetchChallenge(client *http.Client, baseURL string, verbose bool) challengeResp {
	chURL := baseURL + "/join/entra/challenge"
	if verbose {
		fmt.Printf("GET %s\n", chURL)
	}
	resp, err := client.Get(chURL)
	if err != nil {
		die("GET challenge: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		die("challenge returned %d: %s", resp.StatusCode, string(body))
	}
	var challenge challengeResp
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		die("decode challenge: %v", err)
	}
	fmt.Printf("  nonce (expires %s): %s\n", challenge.ExpiresAt.Format(time.RFC3339), challenge.Nonce)
	return challenge
}

func signChallenge(key *rsa.PrivateKey, nonce string) string {
	rawNonce, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		die("decode nonce: %v", err)
	}
	digest := sha256.Sum256(rawNonce)
	sigBytes, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	if err != nil {
		die("sign nonce: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sigBytes)
}

func postEnroll(client *http.Client, opts testerOpts, certB64, nonce, sig, wgPub string) enrollResp {
	req := enrollReq{
		TenantID:       opts.tenant,
		EntraDeviceID:  opts.deviceID,
		CertChain:      []string{certB64},
		Nonce:          nonce,
		NonceSignature: sig,
		WGPubKey:       wgPub,
		Hostname:       opts.hostname,
	}
	body, _ := json.Marshal(req)
	if opts.verbose {
		fmt.Printf("POST %s\n%s\n", opts.baseURL+"/join/entra/enroll", prettyJSON(body))
	}
	httpReq, err := http.NewRequest(http.MethodPost, opts.baseURL+"/join/entra/enroll", bytes.NewReader(body))
	if err != nil {
		die("build enroll request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		die("POST enroll: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var e errorBody
		if jerr := json.Unmarshal(respBody, &e); jerr == nil && e.Code != "" {
			die("enroll failed (%d %s): %s", resp.StatusCode, e.Code, e.Message)
		}
		die("enroll failed (%d): %s", resp.StatusCode, string(respBody))
	}
	var out enrollResp
	if err := json.Unmarshal(respBody, &out); err != nil {
		die("decode enroll response: %v\nraw: %s", err, string(respBody))
	}
	return out
}

func printEnrolmentSuccess(out enrollResp, wgPub string) {
	fmt.Println()
	fmt.Println("====================  ENROLMENT SUCCESS  ====================")
	fmt.Printf("  Peer ID               : %s\n", out.PeerID)
	fmt.Printf("  Resolution mode       : %s\n", out.ResolutionMode)
	fmt.Printf("  Matched mapping IDs   : %v\n", out.MatchedMappingIDs)
	fmt.Printf("  Resolved auto-groups  : %v\n", out.ResolvedAutoGroups)
	fmt.Printf("  Bootstrap token       : %s\n", out.EnrollmentBootstrapToken)
	fmt.Printf("  WG pubkey             : %s\n", wgPub)
	fmt.Println()
	fmt.Println("  The device has been created in NetBird's DB. A real client would")
	fmt.Println("  now start a normal gRPC Sync using this WG pubkey.")
	fmt.Println("=============================================================")
}

func makeCert(deviceID string) (*rsa.PrivateKey, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	return key, base64.StdEncoding.EncodeToString(der), nil
}

func insecureTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = insecureTLSConfig()
	return t
}

func prettyJSON(raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "enroll-tester: "+format+"\n", args...)
	os.Exit(1)
}
