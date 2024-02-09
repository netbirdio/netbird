package detect_cloud

import (
	"net/http"
)

func detectSoftlayer() string {
	resp, err := hc.Get("https://api.service.softlayer.com/rest/v3/SoftLayer_Resource_Metadata/UserMetadata.txt")
	if err == nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		// As SoftLayer was acquired by IBM, we should return IBM Cloud
		return "IBM Cloud"
	}
	return ""
}
