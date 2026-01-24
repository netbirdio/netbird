package tunnel

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultPorts(t *testing.T) {
	assert.Equal(t, 389, PortLDAP)
	assert.Equal(t, 636, PortLDAPS)
	assert.Equal(t, 88, PortKerberos)
	assert.Equal(t, 53, PortDNS)
	assert.Equal(t, 445, PortSMB)
	assert.Equal(t, 123, PortNTP)
	assert.Equal(t, 135, PortRPCEPM)
}

func TestCheckTCPPort_Reachable(t *testing.T) {
	// Start a local TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	// Extract the port
	addr := listener.Addr().(*net.TCPAddr)

	ctx := context.Background()
	result := checkTCPPort(ctx, "127.0.0.1", addr.Port, time.Second)
	assert.True(t, result)
}

func TestCheckTCPPort_Unreachable(t *testing.T) {
	ctx := context.Background()
	// Use a port that's unlikely to be open
	result := checkTCPPort(ctx, "127.0.0.1", 59999, 100*time.Millisecond)
	assert.False(t, result)
}

func TestCheckTCPPort_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := checkTCPPort(ctx, "127.0.0.1", 80, time.Second)
	assert.False(t, result)
}

func TestCheckDCConnectivity_AllUnreachable(t *testing.T) {
	ctx := context.Background()
	// Use an IP that doesn't exist (TEST-NET-1)
	result := CheckDCConnectivity(ctx, "192.0.2.1", 100*time.Millisecond)

	assert.Equal(t, "192.0.2.1", result.DCAddress)
	assert.False(t, result.LDAPReachable)
	assert.False(t, result.KerberosReachable)
	assert.False(t, result.DNSReachable)
	assert.False(t, result.AllRequired)
	assert.NotEmpty(t, result.Errors)
}

func TestCheckDCConnectivity_DefaultTimeout(t *testing.T) {
	ctx := context.Background()
	// This tests that zero timeout uses default
	result := CheckDCConnectivity(ctx, "192.0.2.1", 0)
	// Just verify it doesn't panic and returns a result
	assert.NotNil(t, result)
}

func TestValidatePreJoinRequirements_TunnelDown(t *testing.T) {
	ctx := context.Background()
	checklist := ValidatePreJoinRequirements(ctx, "192.168.100.20", false)

	assert.False(t, checklist.TunnelUp)
	assert.False(t, checklist.ReadyForJoin)
	assert.Contains(t, checklist.Errors, "VPN tunnel is not established")
}

func TestValidatePreJoinRequirements_TunnelUpDCUnreachable(t *testing.T) {
	ctx := context.Background()
	// Use TEST-NET-1 which is unreachable
	checklist := ValidatePreJoinRequirements(ctx, "192.0.2.1", true)

	assert.True(t, checklist.TunnelUp)
	assert.False(t, checklist.ReadyForJoin)
	assert.NotEmpty(t, checklist.Errors)
}

func TestPreJoinChecklist_Fields(t *testing.T) {
	checklist := &PreJoinChecklist{
		TunnelUp:   true,
		TimeInSync: true,
		Errors:     []string{},
		Warnings:   []string{"test warning"},
	}

	assert.True(t, checklist.TunnelUp)
	assert.True(t, checklist.TimeInSync)
	assert.Empty(t, checklist.Errors)
	assert.Len(t, checklist.Warnings, 1)
}

func TestDCConnectivityResult_Fields(t *testing.T) {
	result := &DCConnectivityResult{
		DCAddress:         "192.168.100.20",
		LDAPReachable:     true,
		KerberosReachable: true,
		DNSReachable:      true,
		SMBReachable:      false,
		AllRequired:       true,
		Errors:            []string{},
	}

	assert.Equal(t, "192.168.100.20", result.DCAddress)
	assert.True(t, result.LDAPReachable)
	assert.True(t, result.KerberosReachable)
	assert.True(t, result.DNSReachable)
	assert.False(t, result.SMBReachable)
	assert.True(t, result.AllRequired)
}

func TestGenerateDomainJoinScript_Basic(t *testing.T) {
	config := &DomainJoinConfig{
		DomainName:       "corp.local",
		DCAddress:        "192.168.100.20",
		RestartAfterJoin: false,
		UseCredentials:   false,
	}

	script := GenerateDomainJoinScript(config)

	assert.Contains(t, script, "192.168.100.20")
	assert.Contains(t, script, "corp.local")
	assert.Contains(t, script, "Add-Computer")
	assert.Contains(t, script, "Test-NetConnection")
	assert.Contains(t, script, "w32tm")
	assert.Contains(t, script, "-Restart:$false")
}

func TestGenerateDomainJoinScript_WithRestart(t *testing.T) {
	config := &DomainJoinConfig{
		DomainName:       "corp.local",
		DCAddress:        "192.168.100.20",
		RestartAfterJoin: true,
		UseCredentials:   false,
	}

	script := GenerateDomainJoinScript(config)

	assert.Contains(t, script, "-Restart:$true")
}

func TestGenerateDomainJoinScript_WithCredentials(t *testing.T) {
	config := &DomainJoinConfig{
		DomainName:       "corp.local",
		DCAddress:        "192.168.100.20",
		RestartAfterJoin: false,
		UseCredentials:   true,
	}

	script := GenerateDomainJoinScript(config)

	assert.Contains(t, script, "Get-Credential")
	assert.Contains(t, script, "-Credential")
}

func TestGenerateDomainJoinScript_WithOUPath(t *testing.T) {
	config := &DomainJoinConfig{
		DomainName:       "corp.local",
		DCAddress:        "192.168.100.20",
		OUPath:           "OU=Workstations,DC=corp,DC=local",
		RestartAfterJoin: false,
		UseCredentials:   false,
	}

	script := GenerateDomainJoinScript(config)

	assert.Contains(t, script, "-OUPath")
	assert.Contains(t, script, "OU=Workstations,DC=corp,DC=local")
}

func TestGenerateDomainJoinScript_FullConfig(t *testing.T) {
	config := &DomainJoinConfig{
		DomainName:       "test.local",
		DCAddress:        "10.0.0.1",
		OUPath:           "OU=Computers,DC=test,DC=local",
		RestartAfterJoin: true,
		UseCredentials:   true,
	}

	script := GenerateDomainJoinScript(config)

	// Verify all components are present
	assert.Contains(t, script, "test.local")
	assert.Contains(t, script, "10.0.0.1")
	assert.Contains(t, script, "OU=Computers,DC=test,DC=local")
	assert.Contains(t, script, "-Restart:$true")
	assert.Contains(t, script, "-Credential")

	// Verify the script structure
	assert.Contains(t, script, "# Step 1: Verify DC connectivity")
	assert.Contains(t, script, "# Step 2: Configure NTP")
	assert.Contains(t, script, "# Step 3: Domain Join")
}

func TestMaxKerberosTimeSkew(t *testing.T) {
	assert.Equal(t, 5*time.Minute, MaxKerberosTimeSkew)
}

func TestDefaultConnectTimeout(t *testing.T) {
	assert.Equal(t, 5*time.Second, DefaultConnectTimeout)
}

// TestLocalServerDCConnectivity simulates a partial DC by starting local listeners
func TestLocalServerDCConnectivity(t *testing.T) {
	// Start mock LDAP server
	ldapListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ldapListener.Close()
	ldapPort := ldapListener.Addr().(*net.TCPAddr).Port

	// Start mock Kerberos server
	kerberosListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer kerberosListener.Close()
	kerberosPort := kerberosListener.Addr().(*net.TCPAddr).Port

	// Start mock DNS server
	dnsListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer dnsListener.Close()
	dnsPort := dnsListener.Addr().(*net.TCPAddr).Port

	// Test individual port checks
	ctx := context.Background()
	timeout := 100 * time.Millisecond

	assert.True(t, checkTCPPort(ctx, "127.0.0.1", ldapPort, timeout), "LDAP port should be reachable")
	assert.True(t, checkTCPPort(ctx, "127.0.0.1", kerberosPort, timeout), "Kerberos port should be reachable")
	assert.True(t, checkTCPPort(ctx, "127.0.0.1", dnsPort, timeout), "DNS port should be reachable")

	// Close ports to verify unreachability detection
	ldapListener.Close()
	assert.False(t, checkTCPPort(ctx, "127.0.0.1", ldapPort, timeout), "LDAP port should be unreachable after close")
}

// Test that the result struct properly captures partial connectivity
func TestPartialDCConnectivity(t *testing.T) {
	// Create a result manually to test logic
	result := &DCConnectivityResult{
		DCAddress:         "test.dc",
		LDAPReachable:     true,
		KerberosReachable: false, // Missing Kerberos
		DNSReachable:      true,
		Errors:            []string{fmt.Sprintf("Kerberos (port %d) not reachable", PortKerberos)},
	}

	// Calculate AllRequired
	result.AllRequired = result.LDAPReachable && result.KerberosReachable && result.DNSReachable

	assert.False(t, result.AllRequired, "AllRequired should be false when Kerberos is missing")
	assert.Len(t, result.Errors, 1)
}
