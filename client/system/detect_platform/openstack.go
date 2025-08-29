package detect_platform

import (
	"context"
	"net/http"
)

func detectOpenStack(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/openstack", nil)
	if err != nil {
		return ""
	}

	resp, err := hc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "OpenStack"
	}
	return ""
}
