package detect_cloud

import (
	"context"
	"net/http"
)

func detectAWS(ctx context.Context) string {
	v1ResultChan := make(chan bool, 1)
	v2ResultChan := make(chan bool, 1)

	go func() {
		v1ResultChan <- detectAWSIDMSv1(ctx)
	}()

	go func() {
		v2ResultChan <- detectAWSIDMSv2(ctx)
	}()

	v1Result, v2Result := <-v1ResultChan, <-v2ResultChan

	if v1Result || v2Result {
		return "Amazon Web Services"
	}
	return ""
}

func detectAWSIDMSv1(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/latest/", nil)
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

func detectAWSIDMSv2(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "PUT", "http://169.254.169.254/latest/api/token", nil)
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
