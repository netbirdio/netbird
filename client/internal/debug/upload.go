package debug

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/netbirdio/netbird/upload-server/types"
)

const maxBundleUploadSize = 50 * 1024 * 1024

func UploadDebugBundle(ctx context.Context, url, managementURL, filePath string) (key string, err error) {
	response, err := getUploadURL(ctx, url, managementURL)
	if err != nil {
		return "", err
	}

	err = upload(ctx, filePath, response)
	if err != nil {
		return "", err
	}
	return response.Key, nil
}

func upload(ctx context.Context, filePath string, response *types.GetURLResponse) error {
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

	putResp, err := http.DefaultClient.Do(req)
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

func getUploadURL(ctx context.Context, url string, managementURL string) (*types.GetURLResponse, error) {
	id := getURLHash(managementURL)
	getReq, err := http.NewRequestWithContext(ctx, "GET", url+"?id="+id, nil)
	if err != nil {
		return nil, fmt.Errorf("create GET request: %w", err)
	}

	getReq.Header.Set(types.ClientHeader, types.ClientHeaderValue)

	resp, err := http.DefaultClient.Do(getReq)
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
