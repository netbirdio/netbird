package detect_cloud

import "net/http"

func detectIBMCloud() string {
	req, err := http.NewRequest("PUT", "http://api.metadata.cloud.ibm.com/instance_identity/v1/token", nil)
	if err != nil {
		return ""
	}

	resp, err := hc.Do(req)
	if err != nil {
		req, err = http.NewRequest("PUT", "https://api.metadata.cloud.ibm.com/instance_identity/v1/token", nil)
		if err != nil {
			return ""
		}
		resp, err = hc.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return "IBM Cloud"
	}
	return ""
}
