package detect_cloud

import (
	"net/http"
)

func detectAzure() string {
	req, err := http.NewRequest("GET", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata", "true")

	resp, err := hc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "Microsoft Azure"
	}
	return ""
}
