package detect_cloud

import (
	"context"
	"net/http"
)

func detectOracle(ctx context.Context) string {
	v1ResultChan := make(chan bool, 1)
	v2ResultChan := make(chan bool, 1)

	go func() {
		v1ResultChan <- detectOracleIDMSv1(ctx)
	}()

	go func() {
		v2ResultChan <- detectOracleIDMSv2(ctx)
	}()

	v1Result, v2Result := <-v1ResultChan, <-v2ResultChan

	if v1Result || v2Result {
		return "Oracle"
	}
	return ""
}

func detectOracleIDMSv1(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/opc/v1/instance/", nil)
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

func detectOracleIDMSv2(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/opc/v2/instance/", nil)
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
