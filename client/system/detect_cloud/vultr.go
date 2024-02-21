package detect_cloud

import (
	"context"
	"net/http"
)

func detectVultr(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/v1.json", nil)
	if err != nil {
		return ""
	}

	resp, err := hc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "Vultr"
	}
	return ""
}
