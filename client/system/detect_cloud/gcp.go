package detect_cloud

import (
	"context"
	"net/http"
)

func detectGCP(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254", nil)
	if err != nil {
		return ""
	}
	req.Header.Add("Metadata-Flavor", "Google")

	resp, err := hc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "Google Cloud Platform"
	}
	return ""
}
