package dns

import (
	"testing"
)

func TestGetServerDns(t *testing.T) {
	_, err := GetServerDns()
	if err == nil {
		t.Errorf("invalid dns server instance")
	}

	srv := &MockServer{}
	setServerDns(srv)

	srvB, err := GetServerDns()
	if err != nil {
		t.Errorf("invalid dns server instance: %s", err)
	}

	if srvB != srv {
		t.Errorf("mismatch dns instances")
	}
}
