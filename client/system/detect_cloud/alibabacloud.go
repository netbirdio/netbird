package detect_cloud

import (
	"net/http"
)

func detectAlibabaCloud() string {
	resp, err := hc.Get("http://100.100.100.200/latest/")
	if err == nil && resp.StatusCode == http.StatusOK {
		return "Alibaba Cloud"
	}
	return ""
}
