package detect_cloud

import (
	"net/http"
)

func detectSoftlayer() string {
	resp, err := hc.Get("https://api.service.softlayer.com/rest/v3/SoftLayer_Resource_Metadata/UserMetadata.txt")
	if err == nil && (resp.StatusCode == http.StatusOK) {
		return "SoftLayer"
	}
	return ""
}
