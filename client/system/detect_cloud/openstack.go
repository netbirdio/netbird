package detect_cloud

import (
	"net/http"
)

func detectOpenStack() string {
	resp, err := hc.Get("http://169.254.169.254/openstack")
	if err == nil && (resp.StatusCode == http.StatusOK) {
		return "OpenStack"
	}
	return ""
}
