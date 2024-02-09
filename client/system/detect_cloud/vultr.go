package detect_cloud

import (
	"net/http"
)

func detectVultr() string {
	resp, err := hc.Get("http://169.254.169.254/v1.json")
	if err == nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "Vultr"
	}
	return ""
}
