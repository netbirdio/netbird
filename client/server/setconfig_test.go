package server

import (
	"context"
	"os/user"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// TestSetConfig_AllFieldsSaved ensures that all fields in SetConfigRequest are properly saved to the config.
// This test uses reflection to detect when new fields are added but not handled in SetConfig.
func TestSetConfig_AllFieldsSaved(t *testing.T) {
	tempDir := t.TempDir()
	origDefaultProfileDir := profilemanager.DefaultConfigPathDir
	origDefaultConfigPath := profilemanager.DefaultConfigPath
	origActiveProfileStatePath := profilemanager.ActiveProfileStatePath
	profilemanager.ConfigDirOverride = tempDir
	profilemanager.DefaultConfigPathDir = tempDir
	profilemanager.ActiveProfileStatePath = tempDir + "/active_profile.json"
	profilemanager.DefaultConfigPath = filepath.Join(tempDir, "default.json")
	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDefaultProfileDir
		profilemanager.ActiveProfileStatePath = origActiveProfileStatePath
		profilemanager.DefaultConfigPath = origDefaultConfigPath
		profilemanager.ConfigDirOverride = ""
	})

	currUser, err := user.Current()
	require.NoError(t, err)

	profName := "test-profile"

	ic := profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(tempDir, profName+".json"),
		ManagementURL: "https://api.netbird.io:443",
	}
	_, err = profilemanager.UpdateOrCreateConfig(ic)
	require.NoError(t, err)

	pm := profilemanager.ServiceManager{}
	err = pm.SetActiveProfileState(&profilemanager.ActiveProfileState{
		Name:     profName,
		Username: currUser.Username,
	})
	require.NoError(t, err)

	ctx := context.Background()
	s := New(ctx, "console", "", false, false)

	rosenpassEnabled := true
	rosenpassPermissive := true
	serverSSHAllowed := true
	interfaceName := "utun100"
	wireguardPort := int64(51820)
	preSharedKey := "test-psk"
	disableAutoConnect := true
	networkMonitor := true
	disableClientRoutes := true
	disableServerRoutes := true
	disableDefaultRoute := true
	disableDNS := true
	disableFirewall := true
	blockLANAccess := true
	disableNotifications := true
	lazyConnectionEnabled := true
	blockInbound := true
	mtu := int64(1280)
	sshJWTCacheTTL := int32(300)

	req := &proto.SetConfigRequest{
		ProfileName:           profName,
		Username:              currUser.Username,
		ManagementUrl:         "https://new-api.netbird.io:443",
		AdminURL:              "https://new-admin.netbird.io",
		RosenpassEnabled:      &rosenpassEnabled,
		RosenpassPermissive:   &rosenpassPermissive,
		ServerSSHAllowed:      &serverSSHAllowed,
		InterfaceName:         &interfaceName,
		WireguardPort:         &wireguardPort,
		OptionalPreSharedKey:  &preSharedKey,
		DisableAutoConnect:    &disableAutoConnect,
		NetworkMonitor:        &networkMonitor,
		DisableClientRoutes:   &disableClientRoutes,
		DisableServerRoutes:   &disableServerRoutes,
		DisableDefaultRoute:   &disableDefaultRoute,
		DisableDns:            &disableDNS,
		DisableFirewall:       &disableFirewall,
		BlockLanAccess:        &blockLANAccess,
		DisableNotifications:  &disableNotifications,
		LazyConnectionEnabled: &lazyConnectionEnabled,
		BlockInbound:          &blockInbound,
		NatExternalIPs:        []string{"1.2.3.4", "5.6.7.8"},
		CleanNATExternalIPs:   false,
		CustomDNSAddress:      []byte("1.1.1.1:53"),
		ExtraIFaceBlacklist:   []string{"eth1", "eth2"},
		DnsLabels:             []string{"label1", "label2"},
		CleanDNSLabels:        false,
		DnsRouteInterval:      durationpb.New(2 * time.Minute),
		Mtu:                   &mtu,
		SshJWTCacheTTL:        &sshJWTCacheTTL,
	}

	_, err = s.SetConfig(ctx, req)
	require.NoError(t, err)

	profState := profilemanager.ActiveProfileState{
		Name:     profName,
		Username: currUser.Username,
	}
	cfgPath, err := profState.FilePath()
	require.NoError(t, err)

	cfg, err := profilemanager.GetConfig(cfgPath)
	require.NoError(t, err)

	require.Equal(t, "https://new-api.netbird.io:443", cfg.ManagementURL.String())
	require.Equal(t, "https://new-admin.netbird.io:443", cfg.AdminURL.String())
	require.Equal(t, rosenpassEnabled, cfg.RosenpassEnabled)
	require.Equal(t, rosenpassPermissive, cfg.RosenpassPermissive)
	require.NotNil(t, cfg.ServerSSHAllowed)
	require.Equal(t, serverSSHAllowed, *cfg.ServerSSHAllowed)
	require.Equal(t, interfaceName, cfg.WgIface)
	require.Equal(t, int(wireguardPort), cfg.WgPort)
	require.Equal(t, preSharedKey, cfg.PreSharedKey)
	require.Equal(t, disableAutoConnect, cfg.DisableAutoConnect)
	require.NotNil(t, cfg.NetworkMonitor)
	require.Equal(t, networkMonitor, *cfg.NetworkMonitor)
	require.Equal(t, disableClientRoutes, cfg.DisableClientRoutes)
	require.Equal(t, disableServerRoutes, cfg.DisableServerRoutes)
	require.Equal(t, disableDefaultRoute, cfg.DisableDefaultRoute)
	require.Equal(t, disableDNS, cfg.DisableDNS)
	require.Equal(t, disableFirewall, cfg.DisableFirewall)
	require.Equal(t, blockLANAccess, cfg.BlockLANAccess)
	require.NotNil(t, cfg.DisableNotifications)
	require.Equal(t, disableNotifications, *cfg.DisableNotifications)
	require.Equal(t, lazyConnectionEnabled, cfg.LazyConnectionEnabled)
	require.Equal(t, blockInbound, cfg.BlockInbound)
	require.Equal(t, []string{"1.2.3.4", "5.6.7.8"}, cfg.NATExternalIPs)
	require.Equal(t, "1.1.1.1:53", cfg.CustomDNSAddress)
	// IFaceBlackList contains defaults + extras
	require.Contains(t, cfg.IFaceBlackList, "eth1")
	require.Contains(t, cfg.IFaceBlackList, "eth2")
	require.Equal(t, []string{"label1", "label2"}, cfg.DNSLabels.ToPunycodeList())
	require.Equal(t, 2*time.Minute, cfg.DNSRouteInterval)
	require.Equal(t, uint16(mtu), cfg.MTU)
	require.NotNil(t, cfg.SSHJWTCacheTTL)
	require.Equal(t, int(sshJWTCacheTTL), *cfg.SSHJWTCacheTTL)

	verifyAllFieldsCovered(t, req)
}

// verifyAllFieldsCovered uses reflection to ensure we're testing all fields in SetConfigRequest.
// If a new field is added to SetConfigRequest, this function will fail the test,
// forcing the developer to update both the SetConfig handler and this test.
func verifyAllFieldsCovered(t *testing.T, req *proto.SetConfigRequest) {
	t.Helper()

	metadataFields := map[string]bool{
		"state":               true, // protobuf internal
		"sizeCache":           true, // protobuf internal
		"unknownFields":       true, // protobuf internal
		"Username":            true, // metadata
		"ProfileName":         true, // metadata
		"CleanNATExternalIPs": true, // control flag for clearing
		"CleanDNSLabels":      true, // control flag for clearing
	}

	expectedFields := map[string]bool{
		"ManagementUrl":                 true,
		"AdminURL":                      true,
		"RosenpassEnabled":              true,
		"RosenpassPermissive":           true,
		"ServerSSHAllowed":              true,
		"InterfaceName":                 true,
		"WireguardPort":                 true,
		"OptionalPreSharedKey":          true,
		"DisableAutoConnect":            true,
		"NetworkMonitor":                true,
		"DisableClientRoutes":           true,
		"DisableServerRoutes":           true,
		"DisableDefaultRoute":           true,
		"DisableDns":                    true,
		"DisableFirewall":               true,
		"BlockLanAccess":                true,
		"DisableNotifications":          true,
		"LazyConnectionEnabled":         true,
		"BlockInbound":                  true,
		"NatExternalIPs":                true,
		"CustomDNSAddress":              true,
		"ExtraIFaceBlacklist":           true,
		"DnsLabels":                     true,
		"DnsRouteInterval":              true,
		"Mtu":                           true,
		"EnableSSHRoot":                 true,
		"EnableSSHSFTP":                 true,
		"EnableSSHLocalPortForwarding":  true,
		"EnableSSHRemotePortForwarding": true,
		"DisableSSHAuth":                true,
		"SshJWTCacheTTL":                true,
	}

	val := reflect.ValueOf(req).Elem()
	typ := val.Type()

	var unexpectedFields []string
	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		fieldName := field.Name

		if metadataFields[fieldName] {
			continue
		}

		if !expectedFields[fieldName] {
			unexpectedFields = append(unexpectedFields, fieldName)
		}
	}

	if len(unexpectedFields) > 0 {
		t.Fatalf("New field(s) detected in SetConfigRequest: %v", unexpectedFields)
	}
}

// TestCLIFlags_MappedToSetConfig ensures all CLI flags that modify config are properly mapped to SetConfigRequest.
// This test catches bugs where a new CLI flag is added but not wired to the SetConfigRequest in setupSetConfigReq.
func TestCLIFlags_MappedToSetConfig(t *testing.T) {
	// Map of CLI flag names to their corresponding SetConfigRequest field names.
	// This map must be updated when adding new config-related CLI flags.
	flagToField := map[string]string{
		"management-url":                    "ManagementUrl",
		"admin-url":                         "AdminURL",
		"enable-rosenpass":                  "RosenpassEnabled",
		"rosenpass-permissive":              "RosenpassPermissive",
		"allow-server-ssh":                  "ServerSSHAllowed",
		"interface-name":                    "InterfaceName",
		"wireguard-port":                    "WireguardPort",
		"preshared-key":                     "OptionalPreSharedKey",
		"disable-auto-connect":              "DisableAutoConnect",
		"network-monitor":                   "NetworkMonitor",
		"disable-client-routes":             "DisableClientRoutes",
		"disable-server-routes":             "DisableServerRoutes",
		"disable-default-route":             "DisableDefaultRoute",
		"disable-dns":                       "DisableDns",
		"disable-firewall":                  "DisableFirewall",
		"block-lan-access":                  "BlockLanAccess",
		"block-inbound":                     "BlockInbound",
		"enable-lazy-connection":            "LazyConnectionEnabled",
		"external-ip-map":                   "NatExternalIPs",
		"dns-resolver-address":              "CustomDNSAddress",
		"extra-iface-blacklist":             "ExtraIFaceBlacklist",
		"extra-dns-labels":                  "DnsLabels",
		"dns-router-interval":               "DnsRouteInterval",
		"mtu":                               "Mtu",
		"enable-ssh-root":                   "EnableSSHRoot",
		"enable-ssh-sftp":                   "EnableSSHSFTP",
		"enable-ssh-local-port-forwarding":  "EnableSSHLocalPortForwarding",
		"enable-ssh-remote-port-forwarding": "EnableSSHRemotePortForwarding",
		"disable-ssh-auth":                  "DisableSSHAuth",
		"ssh-jwt-cache-ttl":                 "SshJWTCacheTTL",
	}

	// SetConfigRequest fields that don't have CLI flags (settable only via UI or other means).
	fieldsWithoutCLIFlags := map[string]bool{
		"DisableNotifications": true, // Only settable via UI
	}

	// Get all SetConfigRequest fields to verify our map is complete.
	req := &proto.SetConfigRequest{}
	val := reflect.ValueOf(req).Elem()
	typ := val.Type()

	var unmappedFields []string
	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		fieldName := field.Name

		// Skip protobuf internal fields and metadata fields.
		if fieldName == "state" || fieldName == "sizeCache" || fieldName == "unknownFields" {
			continue
		}
		if fieldName == "Username" || fieldName == "ProfileName" {
			continue
		}
		if fieldName == "CleanNATExternalIPs" || fieldName == "CleanDNSLabels" {
			continue
		}

		// Check if this field is either mapped to a CLI flag or explicitly documented as having no CLI flag.
		mappedToCLI := false
		for _, mappedField := range flagToField {
			if mappedField == fieldName {
				mappedToCLI = true
				break
			}
		}

		hasNoCLIFlag := fieldsWithoutCLIFlags[fieldName]

		if !mappedToCLI && !hasNoCLIFlag {
			unmappedFields = append(unmappedFields, fieldName)
		}
	}

	if len(unmappedFields) > 0 {
		t.Fatalf("SetConfigRequest field(s) not documented: %v\n"+
			"Either add the CLI flag to flagToField map, or if there's no CLI flag for this field, "+
			"add it to fieldsWithoutCLIFlags map with a comment explaining why.", unmappedFields)
	}

	t.Log("All SetConfigRequest fields are properly documented")
}
