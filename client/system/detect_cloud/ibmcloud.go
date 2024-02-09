package detect_cloud

import "net/http"

func detectIBMCloud() string {
	v1ResultChan := make(chan bool, 1)
	v2ResultChan := make(chan bool, 1)

	go func() {
		v1ResultChan <- detectIBMSecure()
	}()

	go func() {
		v2ResultChan <- detectIBM()
	}()

	v1Result, v2Result := <-v1ResultChan, <-v2ResultChan

	if v1Result || v2Result {
		return "IBM Cloud"
	}
	return ""
}

func detectIBMSecure() bool {
	req, err := http.NewRequest("PUT", "https://api.metadata.cloud.ibm.com/instance_identity/v1/token", nil)
	if err != nil {
		return false
	}

	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func detectIBM() bool {
	req, err := http.NewRequest("PUT", "http://api.metadata.cloud.ibm.com/instance_identity/v1/token", nil)
	if err != nil {
		return false
	}

	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
