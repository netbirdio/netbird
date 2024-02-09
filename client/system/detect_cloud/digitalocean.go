package detect_cloud

import (
	"net/http"
)

func detectDigitalOcean() string {
	resp, err := hc.Get("http://169.254.169.254/metadata/v1/")
	if err == nil && resp.StatusCode == http.StatusOK {
		return "Digital Ocean"
	}
	return ""
}
