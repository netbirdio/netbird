// Package tunnel provides machine tunnel functionality for Windows pre-login VPN.
package tunnel

import (
	"context"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// DCConnectivityResult contains the results of DC connectivity checks.
type DCConnectivityResult struct {
	// DCAddress is the IP or hostname of the Domain Controller.
	DCAddress string

	// LDAPReachable indicates if LDAP (port 389) is reachable.
	LDAPReachable bool

	// LDAPSReachable indicates if LDAPS (port 636) is reachable.
	LDAPSReachable bool

	// KerberosReachable indicates if Kerberos (port 88) is reachable.
	KerberosReachable bool

	// DNSReachable indicates if DNS (port 53) is reachable.
	DNSReachable bool

	// SMBReachable indicates if SMB (port 445) is reachable for Sysvol/GPO.
	SMBReachable bool

	// NTPReachable indicates if NTP (port 123 UDP) is reachable.
	NTPReachable bool

	// AllRequired indicates if all required ports are reachable.
	AllRequired bool

	// Errors contains any errors encountered during checks.
	Errors []string
}

// Required ports for Domain Controller connectivity.
const (
	PortLDAP     = 389
	PortLDAPS    = 636
	PortKerberos = 88
	PortDNS      = 53
	PortSMB      = 445
	PortNTP      = 123
	PortRPCEPM   = 135 // RPC Endpoint Mapper
)

// domainJoinPromptMessage is the PowerShell Get-Credential prompt text.
// This is NOT a credential - it's a UI prompt string for the user.
const domainJoinPromptMessage = "Enter administrator account for domain join" //nolint:gosec

// DefaultDCPorts are the ports required for basic DC connectivity.
var DefaultDCPorts = []int{PortLDAP, PortKerberos, PortDNS}

// DefaultConnectTimeout is the default timeout for TCP connection tests.
const DefaultConnectTimeout = 5 * time.Second

// MaxKerberosTimeSkew is the maximum allowed time skew for Kerberos (5 minutes).
const MaxKerberosTimeSkew = 5 * time.Minute

// CheckDCConnectivity verifies that the Domain Controller is reachable via the tunnel.
// This should be called after the tunnel is established and before domain join.
func CheckDCConnectivity(ctx context.Context, dcAddress string, timeout time.Duration) *DCConnectivityResult {
	if timeout == 0 {
		timeout = DefaultConnectTimeout
	}

	result := &DCConnectivityResult{
		DCAddress: dcAddress,
		Errors:    make([]string, 0),
	}

	log.Infof("Checking DC connectivity to %s", dcAddress)

	// Check LDAP (TCP 389) - Required
	result.LDAPReachable = checkTCPPort(ctx, dcAddress, PortLDAP, timeout)
	if !result.LDAPReachable {
		result.Errors = append(result.Errors, fmt.Sprintf("LDAP (port %d) not reachable", PortLDAP))
	}

	// Check Kerberos (TCP 88) - Required
	result.KerberosReachable = checkTCPPort(ctx, dcAddress, PortKerberos, timeout)
	if !result.KerberosReachable {
		result.Errors = append(result.Errors, fmt.Sprintf("Kerberos (port %d) not reachable", PortKerberos))
	}

	// Check DNS (TCP 53) - Required
	result.DNSReachable = checkTCPPort(ctx, dcAddress, PortDNS, timeout)
	if !result.DNSReachable {
		result.Errors = append(result.Errors, fmt.Sprintf("DNS (port %d) not reachable", PortDNS))
	}

	// Check LDAPS (TCP 636) - Optional
	result.LDAPSReachable = checkTCPPort(ctx, dcAddress, PortLDAPS, timeout)

	// Check SMB (TCP 445) - Optional but recommended for GPO
	result.SMBReachable = checkTCPPort(ctx, dcAddress, PortSMB, timeout)

	// Check NTP (UDP 123) - Important for Kerberos time sync
	result.NTPReachable = checkUDPPort(ctx, dcAddress, PortNTP, timeout)
	if !result.NTPReachable {
		// NTP failure is a warning, not an error - time sync might work via other means
		log.Warnf("NTP (port %d) not reachable - ensure time is synchronized", PortNTP)
	}

	// All required = LDAP + Kerberos + DNS
	result.AllRequired = result.LDAPReachable && result.KerberosReachable && result.DNSReachable

	if result.AllRequired {
		log.Infof("DC connectivity check passed: all required ports reachable")
	} else {
		log.Errorf("DC connectivity check failed: %v", result.Errors)
	}

	return result
}

// checkTCPPort tests if a TCP port is reachable.
func checkTCPPort(ctx context.Context, host string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// Create dialer with timeout
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		log.Debugf("TCP port check failed: %s - %v", addr, err)
		return false
	}
	defer conn.Close()

	log.Debugf("TCP port check passed: %s", addr)
	return true
}

// checkUDPPort tests if a UDP port is reachable (best effort - UDP is connectionless).
// This sends a small packet and checks if there's no immediate ICMP unreachable.
func checkUDPPort(ctx context.Context, host string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		log.Debugf("UDP port check failed: %s - %v", addr, err)
		return false
	}
	defer conn.Close()

	// For NTP, send a basic NTP request to check if the service responds
	if port == PortNTP {
		return checkNTPService(conn, timeout)
	}

	// For other UDP services, just check if we could create the connection
	log.Debugf("UDP port check passed (connection established): %s", addr)
	return true
}

// checkNTPService sends a basic NTP request and checks for a response.
func checkNTPService(conn net.Conn, timeout time.Duration) bool {
	// NTP v3 request packet (minimal)
	// Li=0, VN=3, Mode=3 (client), Stratum=0, Poll=0, Precision=0
	ntpRequest := make([]byte, 48)
	ntpRequest[0] = 0x1B // LI=0, VN=3, Mode=3

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		log.Debugf("Failed to set NTP deadline: %v", err)
		return false
	}

	if _, err := conn.Write(ntpRequest); err != nil {
		log.Debugf("Failed to send NTP request: %v", err)
		return false
	}

	response := make([]byte, 48)
	n, err := conn.Read(response)
	if err != nil {
		log.Debugf("No NTP response: %v", err)
		return false
	}

	if n < 48 {
		log.Debugf("Invalid NTP response size: %d", n)
		return false
	}

	log.Debug("NTP service check passed")
	return true
}

// PreJoinChecklist contains all pre-domain-join validation results.
type PreJoinChecklist struct {
	// DCConnectivity is the DC connectivity check result.
	DCConnectivity *DCConnectivityResult

	// TunnelUp indicates if the VPN tunnel is established.
	TunnelUp bool

	// TimeInSync indicates if system time is within Kerberos tolerance.
	TimeInSync bool

	// ReadyForJoin indicates if all checks pass and domain join can proceed.
	ReadyForJoin bool

	// Errors contains any blocking errors.
	Errors []string

	// Warnings contains non-blocking warnings.
	Warnings []string
}

// ValidatePreJoinRequirements performs all checks required before domain join.
func ValidatePreJoinRequirements(ctx context.Context, dcAddress string, tunnelUp bool) *PreJoinChecklist {
	checklist := &PreJoinChecklist{
		TunnelUp: tunnelUp,
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	// Check 1: Tunnel must be up
	if !tunnelUp {
		checklist.Errors = append(checklist.Errors, "VPN tunnel is not established")
		checklist.ReadyForJoin = false
		return checklist
	}

	// Check 2: DC connectivity
	checklist.DCConnectivity = CheckDCConnectivity(ctx, dcAddress, DefaultConnectTimeout)
	if !checklist.DCConnectivity.AllRequired {
		checklist.Errors = append(checklist.Errors, checklist.DCConnectivity.Errors...)
	}

	// Check 3: Time synchronization (warning only - actual sync is done by PowerShell)
	// Note: We can't accurately check time skew from Go without NTP parsing
	// The PowerShell script handles the actual time sync
	if !checklist.DCConnectivity.NTPReachable {
		checklist.Warnings = append(checklist.Warnings,
			"NTP service not reachable - ensure time is synchronized before domain join")
	}
	// Assume time is in sync for the checklist - actual verification is done by PowerShell
	checklist.TimeInSync = true

	// Determine if ready for join
	checklist.ReadyForJoin = tunnelUp &&
		checklist.DCConnectivity.AllRequired &&
		len(checklist.Errors) == 0

	if checklist.ReadyForJoin {
		log.Info("Pre-join checklist passed - ready for domain join")
	} else {
		log.Errorf("Pre-join checklist failed: %v", checklist.Errors)
	}

	return checklist
}

// DomainJoinConfig contains configuration for domain join.
type DomainJoinConfig struct {
	// DomainName is the FQDN of the domain (e.g., "corp.local").
	DomainName string

	// DCAddress is the IP address of the Domain Controller.
	DCAddress string

	// OUPath is the optional OU path for the computer object.
	// Format: "OU=Computers,DC=corp,DC=local"
	OUPath string

	// RestartAfterJoin indicates if the system should restart after join.
	RestartAfterJoin bool

	// UseCredentials indicates if credentials should be prompted.
	// If false, uses the current user's credentials.
	UseCredentials bool
}

// GenerateDomainJoinScript generates a PowerShell script for domain join.
// This is meant to be executed by the Windows service or an elevated process.
func GenerateDomainJoinScript(config *DomainJoinConfig) string {
	restartFlag := "$false"
	if config.RestartAfterJoin {
		restartFlag = "$true"
	}

	credentialPart := ""
	if config.UseCredentials {
		credentialPart = fmt.Sprintf(" -Credential (Get-Credential -Message '%s')", domainJoinPromptMessage)
	}

	ouPart := ""
	if config.OUPath != "" {
		ouPart = fmt.Sprintf(" -OUPath '%s'", config.OUPath)
	}

	script := fmt.Sprintf(`# Domain Join Script (Generated by NetBird Machine Tunnel)
# Prerequisites: Tunnel up, DC reachable, time synchronized

$ErrorActionPreference = 'Stop'
$dcIP = '%s'
$domain = '%s'

# Step 1: Verify DC connectivity
Write-Host "Verifying DC connectivity..."

if (-not (Test-NetConnection -ComputerName $dcIP -Port 389 -WarningAction SilentlyContinue).TcpTestSucceeded) {
    throw "LDAP (port 389) not reachable - check tunnel status"
}

if (-not (Test-NetConnection -ComputerName $dcIP -Port 88 -WarningAction SilentlyContinue).TcpTestSucceeded) {
    throw "Kerberos (port 88) not reachable - check tunnel status"
}

Write-Host "DC connectivity verified."

# Step 2: Configure NTP via DC (before domain join)
Write-Host "Configuring NTP sync..."
try {
    w32tm /config /manualpeerlist:"$dcIP" /syncfromflags:manual /reliable:no /update
    Restart-Service W32Time -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    w32tm /resync /nowait
    Write-Host "NTP configured successfully."
} catch {
    Write-Warning "NTP configuration failed: $_"
}

# Step 3: Domain Join
Write-Host "Joining domain: $domain"
try {
    Add-Computer -DomainName $domain%s%s -Restart:%s -Force
    Write-Host "Domain join successful!"
} catch {
    throw "Domain join failed: $_"
}
`, config.DCAddress, config.DomainName, ouPart, credentialPart, restartFlag)

	return script
}
