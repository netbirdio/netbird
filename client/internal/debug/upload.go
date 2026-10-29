package debug

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"

	"github.com/netbirdio/netbird/upload-server/types"
)

const maxBundleUploadSize = 50 * 1024 * 1024

// requireHTTPS refuses any URL the daemon would fetch or upload to that is not
// https. The daemon runs as root and the bundle carries its logs and state, so a
// plaintext hop is a place to intercept the bundle or the presigned redirect.
// The server-side gate already enforces this for the desktop path; this also
// covers the mobile and job-runner callers that reach this package directly.
// Skipped when the caller opted into an insecure upload (self-hosted server).
func requireHTTPS(what, rawURL string) error {
	parsed, err := neturl.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse %s: %w", what, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("%s must use https, got scheme %q", what, parsed.Scheme)
	}
	return nil
}

// uploadClient returns the HTTP client for the upload requests. The default
// client verifies TLS and refuses a redirect that would downgrade to a non-https
// hop, so a bundle can never leave over http after an https start. The insecure
// variant accepts http and untrusted certificates, and is only reachable for a
// privileged caller that passed --upload-bundle-insecure (see
// requirePrivilegeForUploadURL).
func uploadClient(insecure bool) *http.Client {
	if !insecure {
		return &http.Client{CheckRedirect: rejectInsecureRedirect}
	}
	return &http.Client{
		Transport: &http.Transport{
			//nolint:gosec // opt-in, privileged, self-hosted upload servers
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
	}
}

// rejectInsecureRedirect refuses a redirect to a non-https target and keeps the
// standard library's 10-hop limit that a custom CheckRedirect would otherwise
// disable.
func rejectInsecureRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-https URL %s", req.URL.Redacted())
	}
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	return nil
}

func UploadDebugBundle(ctx context.Context, url, managementURL, filePath string, insecure bool) (key string, err error) {
	if !insecure {
		if err := requireHTTPS("upload service URL", url); err != nil {
			return "", err
		}
	}

	response, err := getUploadURL(ctx, url, managementURL, insecure)
	if err != nil {
		return "", err
	}

	if !insecure {
		if err := requireHTTPS("upload URL from service", response.URL); err != nil {
			return "", err
		}
	}

	err = upload(ctx, filePath, response, insecure)
	if err != nil {
		return "", err
	}
	return response.Key, nil
}

func upload(ctx context.Context, filePath string, response *types.GetURLResponse, insecure bool) error {
	fileData, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}

	defer fileData.Close()

	stat, err := fileData.Stat()
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}

	if stat.Size() > maxBundleUploadSize {
		return fmt.Errorf("file size exceeds maximum limit of %d bytes", maxBundleUploadSize)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", response.URL, fileData)
	if err != nil {
		return fmt.Errorf("create PUT request: %w", err)
	}

	req.ContentLength = stat.Size()
	req.Header.Set("Content-Type", "application/octet-stream")

	putResp, err := uploadClient(insecure).Do(req)
	if err != nil {
		return fmt.Errorf("upload failed: %v", err)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(putResp.Body)
		return fmt.Errorf("upload status %d: %s", putResp.StatusCode, string(body))
	}
	return nil
}

func getUploadURL(ctx context.Context, serviceURL string, managementURL string, insecure bool) (*types.GetURLResponse, error) {
	parsed, err := neturl.Parse(serviceURL)
	if err != nil {
		return nil, fmt.Errorf("parse upload service URL: %w", err)
	}
	q := parsed.Query()
	q.Set("id", getURLHash(managementURL))
	parsed.RawQuery = q.Encode()

	getReq, err := http.NewRequestWithContext(ctx, "GET", parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create GET request: %w", err)
	}

	getReq.Header.Set(types.ClientHeader, types.ClientHeaderValue)

	resp, err := uploadClient(insecure).Do(getReq)
	if err != nil {
		return nil, fmt.Errorf("get presigned URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get presigned URL status %d: %s", resp.StatusCode, string(body))
	}

	urlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	var response types.GetURLResponse
	if err := json.Unmarshal(urlBytes, &response); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return &response, nil
}

func getURLHash(url string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(url)))
}
