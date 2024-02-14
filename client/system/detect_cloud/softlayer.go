package detect_cloud

import (
	"context"
	"net/http"
)

func detectSoftlayer(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.service.softlayer.com/rest/v3/SoftLayer_Resource_Metadata/UserMetadata.txt", nil)
	if err != nil {
		return ""
	}

	resp, err := hc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		// Since SoftLayer was acquired by IBM, we should return "IBM Cloud"
		return "IBM Cloud"
	}
	return ""
}
