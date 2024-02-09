package detect_cloud

import (
	"net/http"
)

func detectAlibabaCloud() string {
	resp, err := hc.Get("http://100.100.100.200/latest/")
	if err == nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "Alibaba Cloud"
	}
	return ""
}
