package detect_cloud

import (
	"context"
	"net/http"
)

func detectIBMCloud(ctx context.Context) string {
	v1ResultChan := make(chan bool, 1)
	v2ResultChan := make(chan bool, 1)

	go func() {
		v1ResultChan <- detectIBMSecure(ctx)
	}()

	go func() {
		v2ResultChan <- detectIBM(ctx)
	}()

	v1Result, v2Result := <-v1ResultChan, <-v2ResultChan

	if v1Result || v2Result {
		return "IBM Cloud"
	}
	return ""
}

func detectIBMSecure(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "PUT", "https://api.metadata.cloud.ibm.com/instance_identity/v1/token", nil)
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

func detectIBM(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "PUT", "http://api.metadata.cloud.ibm.com/instance_identity/v1/token", nil)
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
