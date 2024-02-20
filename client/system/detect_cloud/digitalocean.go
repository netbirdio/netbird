package detect_cloud

import (
	"context"
	"net/http"
)

func detectDigitalOcean(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/metadata/v1/", nil)
	if err != nil {
		return ""
	}

	resp, err := hc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "Digital Ocean"
	}
	return ""
}
