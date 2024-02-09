package detect_cloud

import "net/http"

func detectOracle() string {
	v1ResultChan := make(chan bool, 1)
	v2ResultChan := make(chan bool, 1)

	go func() {
		v1ResultChan <- detectOracleIDMSv1()
	}()

	go func() {
		v2ResultChan <- detectOracleIDMSv2()
	}()

	v1Result, v2Result := <-v1ResultChan, <-v2ResultChan

	if v1Result || v2Result {
		return "Oracle"
	}
	return ""
}

func detectOracleIDMSv1() bool {
	req, err := http.NewRequest("GET", "http://169.254.169.254/opc/v1/instance/", nil)
	if err != nil {
		return false
	}
	req.Header.Add("Authorization", "Bearer Oracle")

	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func detectOracleIDMSv2() bool {
	req, err := http.NewRequest("GET", "http://169.254.169.254/opc/v2/instance/", nil)
	if err != nil {
		return false
	}
	req.Header.Add("Authorization", "Bearer Oracle")

	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
