package detect_cloud

import (
	"context"
	"net/http"
)

func detectAlibabaCloud(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://100.100.100.200/latest/", nil)
	if err != nil {
		return ""
	}

	resp, err := hc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "Alibaba Cloud"
	}
	return ""
}
