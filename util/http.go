package util

import (
	"crypto/tls"
	"net/http"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	disableCertValidationKey = "NB_DISABLE_CERT_VALIDATION"
)

// NewTransport creates a new HTTP transport with optional certificate validation disabled.
func NewTransport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if os.Getenv(disableCertValidationKey) == "true" {
		log.Warnf("HTTP client certificate validation is disabled")
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		tr.TLSClientConfig.InsecureSkipVerify = true
	}
	return tr
}

// NewHTTPClient creates a new HTTP client with optional certificate validation disabled.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: NewTransport(),
		Timeout:   10 * time.Second,
	}
}
