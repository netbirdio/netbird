package detect_cloud

import (
	"net/http"
)

func detectAWS() string {
	v1ResultChan := make(chan bool, 1)
	v2ResultChan := make(chan bool, 1)

	go func() {
		v1ResultChan <- detectAWSIDMSv1()
	}()

	go func() {
		v2ResultChan <- detectAWSIDMSv2()
	}()

	v1Result, v2Result := <-v1ResultChan, <-v2ResultChan

	if v1Result || v2Result {
		return "Amazon Web Services"
	}
	return ""
}

func detectAWSIDMSv1() bool {
	resp, err := hc.Get("http://169.254.169.254/latest/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func detectAWSIDMSv2() bool {
	req, err := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
