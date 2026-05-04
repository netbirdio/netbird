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

	mockSrvB, ok := srvB.(*MockServer)
	if !ok {
		t.Errorf("returned server is not a MockServer")
	}

	if mockSrvB != srv {
		t.Errorf("mismatch dns instances")
	}
}
