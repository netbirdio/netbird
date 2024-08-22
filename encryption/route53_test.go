package encryption

import (
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestRoute53TLSConfig(t *testing.T) {
	t.SkipNow() // This test requires AWS credentials
	exampleString := "Hello, world!"
	rtls := &Route53TLS{
		DataDir: t.TempDir(),
		Email:   os.Getenv("LE_EMAIL_ROUTE53"),
		Domains: []string{os.Getenv("DOMAIN")},
	}
	tlsConfig, err := rtls.GetCertificate()
	if err != nil {
		t.Errorf("Route53TLSConfig failed: %v", err)
	}

	server := &http.Server{
		Addr: ":8443",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(exampleString))
		}),
		TLSConfig: tlsConfig,
	}

	go func() {
		err := server.ListenAndServeTLS("", "")
		if err != http.ErrServerClosed {
			t.Errorf("Failed to start server: %v", err)
		}
	}()
	defer func() {
		if err := server.Shutdown(context.Background()); err != nil {
			t.Errorf("Failed to shutdown server: %v", err)
		}
	}()

	time.Sleep(1 * time.Second)
	resp, err := http.Get("https://relay.godevltd.com:8443")
	if err != nil {
		t.Errorf("Failed to get response: %v", err)
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("Failed to read response body: %v", err)
	}
	if string(body) != exampleString {
		t.Errorf("Unexpected response: %s", body)
	}
}

func Test_emailFromDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "admin@example.com"},
		{"x.example.com", "admin@example.com"},
		{"x.x.example.com", "admin@example.com"},
		{"*.example.com", "admin@example.com"},
		{"example", ""},
		{"", ""},
		{".com", ""},
	}
	for _, tt := range tests {
		t.Run("domain test", func(t *testing.T) {
			if got := emailFromDomain(tt.input); got != tt.want {
				t.Errorf("emailFromDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}
