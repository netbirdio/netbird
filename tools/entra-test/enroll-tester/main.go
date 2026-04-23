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

func main() {
	var (
		baseURL  = flag.String("url", "http://localhost:33081", "Base URL of the management HTTP server (no trailing slash, no /join/entra suffix)")
		tenant   = flag.String("tenant", "", "Entra tenant ID registered on the server (required)")
		deviceID = flag.String("device-id", "test-device-0000-0000-0000-000000000001", "Entra device ID. Used as the cert Subject CN.")
		hostname = flag.String("hostname", "", "Hostname to present to the server. Defaults to device-<id>.")
		insecure = flag.Bool("insecure", false, "Skip TLS certificate verification (useful for self-signed dev setups)")
		verbose  = flag.Bool("v", false, "Print request/response bodies")
	)
	flag.Parse()

	if *tenant == "" {
		fmt.Fprintln(os.Stderr, "error: --tenant is required")
		flag.Usage()
		os.Exit(2)
	}
	if *hostname == "" {
		*hostname = "device-" + *deviceID
	}

	client := &http.Client{Timeout: 15 * time.Second}
	if *insecure {
		client.Transport = insecureTransport()
	}

	// 1. Generate a fake device cert.
	key, certB64, err := makeCert(*deviceID)
	if err != nil {
		die("generate cert: %v", err)
	}
	if *verbose {
		fmt.Printf("Generated self-signed RSA cert for CN=%s (%d chars DER-b64)\n", *deviceID, len(certB64))
	}

	// 2. Generate a fake WireGuard pubkey (32 random bytes, base64).
	wgBytes := make([]byte, 32)
	if _, err := rand.Read(wgBytes); err != nil {
		die("generate wg pubkey: %v", err)
	}
	wgPub := base64.StdEncoding.EncodeToString(wgBytes)

	// 3. Fetch challenge.
	chURL := *baseURL + "/join/entra/challenge"
	if *verbose {
		fmt.Printf("GET %s\n", chURL)
	}
	chResp, err := client.Get(chURL)
	if err != nil {
		die("GET challenge: %v", err)
	}
	defer chResp.Body.Close()
	if chResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(chResp.Body)
		die("challenge returned %d: %s", chResp.StatusCode, string(body))
	}
	var challenge challengeResp
	if err := json.NewDecoder(chResp.Body).Decode(&challenge); err != nil {
		die("decode challenge: %v", err)
	}
	fmt.Printf("  nonce (expires %s): %s\n", challenge.ExpiresAt.Format(time.RFC3339), challenge.Nonce)

	// 4. Sign the raw nonce bytes.
	rawNonce, err := base64.RawURLEncoding.DecodeString(challenge.Nonce)
	if err != nil {
		die("decode nonce: %v", err)
	}
	digest := sha256.Sum256(rawNonce)
	sigBytes, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	if err != nil {
		die("sign nonce: %v", err)
	}
	sig := base64.StdEncoding.EncodeToString(sigBytes)

	// 5. Enroll.
	req := enrollReq{
		TenantID:       *tenant,
		EntraDeviceID:  *deviceID,
		CertChain:      []string{certB64},
		Nonce:          challenge.Nonce,
		NonceSignature: sig,
		WGPubKey:       wgPub,
		Hostname:       *hostname,
	}
	body, _ := json.Marshal(req)
	if *verbose {
		fmt.Printf("POST %s\n%s\n", *baseURL+"/join/entra/enroll", prettyJSON(body))
	}
	httpReq, err := http.NewRequest(http.MethodPost, *baseURL+"/join/entra/enroll", bytes.NewReader(body))
	if err != nil {
		die("build enroll request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	enResp, err := client.Do(httpReq)
	if err != nil {
		die("POST enroll: %v", err)
	}
	defer enResp.Body.Close()
	respBody, _ := io.ReadAll(enResp.Body)

	if enResp.StatusCode != http.StatusOK {
		var e errorBody
		if jerr := json.Unmarshal(respBody, &e); jerr == nil && e.Code != "" {
			die("enroll failed (%d %s): %s", enResp.StatusCode, e.Code, e.Message)
		}
		die("enroll failed (%d): %s", enResp.StatusCode, string(respBody))
	}

	var out enrollResp
	if err := json.Unmarshal(respBody, &out); err != nil {
		die("decode enroll response: %v\nraw: %s", err, string(respBody))
	}

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
