package NetBirdSDK

import (
	"path/filepath"
	"testing"

	"github.com/netbirdio/netbird/client/internal"
)

func TestPreferences_DefaultValues(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "netbird.json")
	p := NewPreferences(cfgFile)
	defaultVar, err := p.GetAdminURL()
	if err != nil {
		t.Fatalf("failed to read default value: %s", err)
	}

	if defaultVar != internal.DefaultAdminURL {
		t.Errorf("invalid default admin url: %s", defaultVar)
	}

	defaultVar, err = p.GetManagementURL()
	if err != nil {
		t.Fatalf("failed to read default management URL: %s", err)
	}

	if defaultVar != internal.DefaultManagementURL {
		t.Errorf("invalid default management url: %s", defaultVar)
	}

	var preSharedKey string
	preSharedKey, err = p.GetPreSharedKey()
	if err != nil {
		t.Fatalf("failed to read default preshared key: %s", err)
	}

	if preSharedKey != "" {
		t.Errorf("invalid preshared key: %s", preSharedKey)
	}
}

func TestPreferences_ReadUncommitedValues(t *testing.T) {
	exampleString := "exampleString"
	cfgFile := filepath.Join(t.TempDir(), "netbird.json")
	p := NewPreferences(cfgFile)

	p.SetAdminURL(exampleString)
	resp, err := p.GetAdminURL()
	if err != nil {
		t.Fatalf("failed to read admin url: %s", err)
	}

	if resp != exampleString {
		t.Errorf("unexpected admin url: %s", resp)
	}

	p.SetManagementURL(exampleString)
	resp, err = p.GetManagementURL()
	if err != nil {
		t.Fatalf("failed to read management url: %s", err)
	}

	if resp != exampleString {
		t.Errorf("unexpected management url: %s", resp)
	}

	p.SetPreSharedKey(exampleString)
	resp, err = p.GetPreSharedKey()
	if err != nil {
		t.Fatalf("failed to read preshared key: %s", err)
	}

	if resp != exampleString {
		t.Errorf("unexpected preshared key: %s", resp)
	}
}

func TestPreferences_Commit(t *testing.T) {
	exampleURL := "https://myurl.com:443"
	examplePresharedKey := "topsecret"
	cfgFile := filepath.Join(t.TempDir(), "netbird.json")
	p := NewPreferences(cfgFile)

	p.SetAdminURL(exampleURL)
	p.SetManagementURL(exampleURL)
	p.SetPreSharedKey(examplePresharedKey)

	err := p.Commit()
	if err != nil {
		t.Fatalf("failed to save changes: %s", err)
	}

	p = NewPreferences(cfgFile)
	resp, err := p.GetAdminURL()
	if err != nil {
		t.Fatalf("failed to read admin url: %s", err)
	}

	if resp != exampleURL {
		t.Errorf("unexpected admin url: %s", resp)
	}

	resp, err = p.GetManagementURL()
	if err != nil {
		t.Fatalf("failed to read management url: %s", err)
	}

	if resp != exampleURL {
		t.Errorf("unexpected management url: %s", resp)
	}

	resp, err = p.GetPreSharedKey()
	if err != nil {
		t.Fatalf("failed to read preshared key: %s", err)
	}

	if resp != examplePresharedKey {
		t.Errorf("unexpected preshared key: %s", resp)
	}
}
