package android

import (
	"path/filepath"
	"testing"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

func TestPreferences_DefaultValues(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "netbird.json")
	p := NewPreferences(cfgFile)
	defaultVar, err := p.GetAdminURL()
	if err != nil {
		t.Fatalf("failed to read default value: %s", err)
	}

	if defaultVar != profilemanager.DefaultAdminURL {
		t.Errorf("invalid default admin url: %s", defaultVar)
	}

	defaultVar, err = p.GetManagementURL()
	if err != nil {
		t.Fatalf("failed to read default management URL: %s", err)
	}

	if defaultVar != profilemanager.DefaultManagementURL {
		t.Errorf("invalid default management url: %s", defaultVar)
	}

	hasPSK, err := p.HasPreSharedKey()
	if err != nil {
		t.Fatalf("failed to read default preshared key presence: %s", err)
	}

	if hasPSK {
		t.Errorf("unexpected preshared key presence on fresh config")
	}
}

func TestPreferences_ReadUncommitedValues(t *testing.T) {
	exampleString := "exampleString"
	cfgFile := filepath.Join(t.TempDir(), "netbird.json")
	p := NewPreferences(cfgFile)

	// The admin URL is deprecated: setting it is a no-op.
	p.SetAdminURL(exampleString)
	resp, err := p.GetAdminURL()
	if err != nil {
		t.Fatalf("failed to read admin url: %s", err)
	}

	if resp != profilemanager.DefaultAdminURL {
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
	hasPSK, err := p.HasPreSharedKey()
	if err != nil {
		t.Fatalf("failed to read preshared key presence: %s", err)
	}

	if !hasPSK {
		t.Errorf("expected preshared key presence after staging one")
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

	if resp != profilemanager.DefaultAdminURL {
		t.Errorf("unexpected admin url: %s", resp)
	}

	resp, err = p.GetManagementURL()
	if err != nil {
		t.Fatalf("failed to read management url: %s", err)
	}

	if resp != exampleURL {
		t.Errorf("unexpected management url: %s", resp)
	}

	hasPSK, err := p.HasPreSharedKey()
	if err != nil {
		t.Fatalf("failed to read preshared key presence: %s", err)
	}

	if !hasPSK {
		t.Errorf("expected preshared key presence after commit")
	}
}

type jsonFetcher string

func (f jsonFetcher) FetchJSON() string { return string(f) }

func TestPreferences_MDMNetworkKeysBeatLocalValues(t *testing.T) {
	p := NewPreferences(filepath.Join(t.TempDir(), "netbird.json"))
	p.SetDisableDNS(false)
	p.SetDisableFirewall(false)
	p.SetDisableIPv6(false)
	p.SetMDMPolicyFetcher(jsonFetcher(`{"disableDNS": true, "disableFirewall": "true", "disableIPv6": true}`))

	for name, get := range map[string]func() (bool, error){
		"disableDNS":      p.GetDisableDNS,
		"disableFirewall": p.GetDisableFirewall,
		"disableIPv6":     p.GetDisableIPv6,
	} {
		got, err := get()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !got {
			t.Errorf("%s: the MDM value must win over the staged local value", name)
		}
	}
}
