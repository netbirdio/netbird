//go:build windows

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"unsafe"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	ExitCodeSuccess           = 0
	ExitCodeLogonFail         = 10
	ExitCodeCreateProcessFail = 11
	ExitCodeWorkingDirFail    = 12
	ExitCodeShellExecFail     = 13
	ExitCodeValidationFail    = 14
)

type WindowsExecutorConfig struct {
	Username   string
	Domain     string
	WorkingDir string
	Shell      string
	Command    string
	Args       []string
	Pty        bool
	PtyWidth   int
	PtyHeight  int
}

type PrivilegeDropper struct {
	logger *log.Entry
}

// PrivilegeDropperOption is a functional option for configuring PrivilegeDropper
type PrivilegeDropperOption func(*PrivilegeDropper)

func NewPrivilegeDropper(opts ...PrivilegeDropperOption) *PrivilegeDropper {
	pd := &PrivilegeDropper{}
	for _, opt := range opts {
		opt(pd)
	}
	return pd
}

// WithLogger sets the logger for the PrivilegeDropper
func WithLogger(logger *log.Entry) PrivilegeDropperOption {
	return func(pd *PrivilegeDropper) {
		pd.logger = logger
	}
}

// log returns the logger, falling back to standard logger if none set
func (pd *PrivilegeDropper) log() *log.Entry {
	if pd.logger != nil {
		return pd.logger
	}
	return log.NewEntry(log.StandardLogger())
}

var (
	advapi32                    = windows.NewLazyDLL("advapi32.dll")
	procAllocateLocallyUniqueId = advapi32.NewProc("AllocateLocallyUniqueId")
)

const (
	logon32LogonNetwork = 3 // Network logon - no password required for authenticated users

	// Common error messages
	commandFlag          = "-Command"
	convertUsernameError = "convert username to UTF16: %w"
	convertDomainError   = "convert domain to UTF16: %w"
)

// CreateWindowsExecutorCommand creates a Windows command with privilege dropping.
// The caller must close the returned token handle after starting the process.
func (pd *PrivilegeDropper) CreateWindowsExecutorCommand(ctx context.Context, config WindowsExecutorConfig) (*exec.Cmd, windows.Token, error) {
	if config.Username == "" {
		return nil, 0, errors.New("username cannot be empty")
	}
	if config.Shell == "" {
		return nil, 0, errors.New("shell cannot be empty")
	}

	shell := config.Shell

	var shellArgs []string
	if config.Command != "" {
		shellArgs = []string{shell, commandFlag, config.Command}
	} else {
		shellArgs = []string{shell}
	}

	pd.log().Tracef("creating Windows direct shell command: %s %v", shellArgs[0], shellArgs)

	cmd, token, err := pd.CreateWindowsProcessAsUser(
		ctx, shellArgs[0], shellArgs, config.Username, config.Domain, config.WorkingDir)
	if err != nil {
		return nil, 0, fmt.Errorf("create Windows process as user: %w", err)
	}

	return cmd, token, nil
}

const (
	// StatusSuccess represents successful LSA operation
	StatusSuccess = 0

	// KerbS4ULogonType message type for domain users with Kerberos
	KerbS4ULogonType = 12
	// Msv10s4ulogontype message type for local users with MSV1_0
	Msv10s4ulogontype = 12

	// MicrosoftKerberosNameA is the authentication package name for Kerberos
	MicrosoftKerberosNameA = "Kerberos"
	// Msv10packagename is the authentication package name for MSV1_0
	Msv10packagename = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"

	NameSamCompatible = 2
	NameUserPrincipal = 8
	NameCanonical     = 7

	maxUPNLen = 1024
)

// kerbS4ULogon structure for S4U authentication (domain users)
type kerbS4ULogon struct {
	MessageType uint32
	Flags       uint32
	ClientUpn   unicodeString
	ClientRealm unicodeString
}

// msv10s4ulogon structure for S4U authentication (local users)
type msv10s4ulogon struct {
	MessageType       uint32
	Flags             uint32
	UserPrincipalName unicodeString
	DomainName        unicodeString
}

// unicodeString structure
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// lsaString structure
type lsaString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *byte
}

// tokenSource structure
type tokenSource struct {
	SourceName       [8]byte
	SourceIdentifier windows.LUID
}

// quotaLimits structure
type quotaLimits struct {
	PagedPoolLimit        uint32
	NonPagedPoolLimit     uint32
	MinimumWorkingSetSize uint32
	MaximumWorkingSetSize uint32
	PagefileLimit         uint32
	TimeLimit             int64
}

var (
	secur32                            = windows.NewLazyDLL("secur32.dll")
	procLsaRegisterLogonProcess        = secur32.NewProc("LsaRegisterLogonProcess")
	procLsaLookupAuthenticationPackage = secur32.NewProc("LsaLookupAuthenticationPackage")
	procLsaLogonUser                   = secur32.NewProc("LsaLogonUser")
	procLsaFreeReturnBuffer            = secur32.NewProc("LsaFreeReturnBuffer")
	procLsaDeregisterLogonProcess      = secur32.NewProc("LsaDeregisterLogonProcess")
	procTranslateNameW                 = secur32.NewProc("TranslateNameW")
)

// newLsaString creates an LsaString from a Go string
func newLsaString(s string) lsaString {
	b := append([]byte(s), 0)
	return lsaString{
		Length:        uint16(len(s)),
		MaximumLength: uint16(len(b)),
		Buffer:        &b[0],
	}
}

// generateS4UUserToken creates a Windows token using S4U authentication
// This is the exact approach OpenSSH for Windows uses for public key authentication
func generateS4UUserToken(logger *log.Entry, username, domain string) (windows.Handle, error) {
	userCpn := buildUserCpn(username, domain)

	pd := NewPrivilegeDropper(WithLogger(logger))
	isDomainUser := !pd.isLocalUser(domain)

	lsaHandle, err := initializeLsaConnection()
	if err != nil {
		return 0, err
	}
	defer cleanupLsaConnection(lsaHandle)

	authPackageId, err := lookupAuthenticationPackage(lsaHandle, isDomainUser)
	if err != nil {
		return 0, err
	}

	logonInfo, logonInfoSize, err := prepareS4ULogonStructure(logger, username, domain, isDomainUser)
	if err != nil {
		return 0, err
	}

	return performS4ULogon(logger, lsaHandle, authPackageId, logonInfo, logonInfoSize, userCpn, isDomainUser)
}

// buildUserCpn constructs the user principal name
func buildUserCpn(username, domain string) string {
	if domain != "" && domain != "." {
		return fmt.Sprintf(`%s\%s`, domain, username)
	}
	return username
}

// initializeLsaConnection establishes connection to LSA
func initializeLsaConnection() (windows.Handle, error) {

	processName := newLsaString("NetBird")
	var mode uint32
	var lsaHandle windows.Handle
	ret, _, _ := procLsaRegisterLogonProcess.Call(
		uintptr(unsafe.Pointer(&processName)),
		uintptr(unsafe.Pointer(&lsaHandle)),
		uintptr(unsafe.Pointer(&mode)),
	)
	if ret != StatusSuccess {
		return 0, fmt.Errorf("LsaRegisterLogonProcess: 0x%x", ret)
	}

	return lsaHandle, nil
}

// cleanupLsaConnection closes the LSA connection
func cleanupLsaConnection(lsaHandle windows.Handle) {
	if ret, _, _ := procLsaDeregisterLogonProcess.Call(uintptr(lsaHandle)); ret != StatusSuccess {
		log.Debugf("LsaDeregisterLogonProcess failed: 0x%x", ret)
	}
}

// lookupAuthenticationPackage finds the correct authentication package
func lookupAuthenticationPackage(lsaHandle windows.Handle, isDomainUser bool) (uint32, error) {
	var authPackageName lsaString
	if isDomainUser {
		authPackageName = newLsaString(MicrosoftKerberosNameA)
	} else {
		authPackageName = newLsaString(Msv10packagename)
	}

	var authPackageId uint32
	ret, _, _ := procLsaLookupAuthenticationPackage.Call(
		uintptr(lsaHandle),
		uintptr(unsafe.Pointer(&authPackageName)),
		uintptr(unsafe.Pointer(&authPackageId)),
	)
	if ret != StatusSuccess {
		return 0, fmt.Errorf("LsaLookupAuthenticationPackage: 0x%x", ret)
	}

	return authPackageId, nil
}

// lookupPrincipalName converts DOMAIN\username to username@domain.fqdn (UPN format)
func lookupPrincipalName(username, domain string) (string, error) {
	samAccountName := fmt.Sprintf(`%s\%s`, domain, username)
	samAccountNameUtf16, err := windows.UTF16PtrFromString(samAccountName)
	if err != nil {
		return "", fmt.Errorf("convert SAM account name to UTF-16: %w", err)
	}

	upnBuf := make([]uint16, maxUPNLen+1)
	upnSize := uint32(len(upnBuf))

	ret, _, _ := procTranslateNameW.Call(
		uintptr(unsafe.Pointer(samAccountNameUtf16)),
		uintptr(NameSamCompatible),
		uintptr(NameUserPrincipal),
		uintptr(unsafe.Pointer(&upnBuf[0])),
		uintptr(unsafe.Pointer(&upnSize)),
	)

	if ret != 0 {
		upn := windows.UTF16ToString(upnBuf[:upnSize])
		log.Debugf("Translated %s to explicit UPN: %s", samAccountName, upn)
		return upn, nil
	}

	upnSize = uint32(len(upnBuf))
	ret, _, _ = procTranslateNameW.Call(
		uintptr(unsafe.Pointer(samAccountNameUtf16)),
		uintptr(NameSamCompatible),
		uintptr(NameCanonical),
		uintptr(unsafe.Pointer(&upnBuf[0])),
		uintptr(unsafe.Pointer(&upnSize)),
	)

	if ret != 0 {
		canonical := windows.UTF16ToString(upnBuf[:upnSize])
		slashIdx := strings.IndexByte(canonical, '/')
		if slashIdx > 0 {
			fqdn := canonical[:slashIdx]
			upn := fmt.Sprintf("%s@%s", username, fqdn)
			log.Debugf("Translated %s to implicit UPN: %s (from canonical: %s)", samAccountName, upn, canonical)
			return upn, nil
		}
	}

	log.Debugf("Could not translate %s to UPN, using SAM format", samAccountName)
	return samAccountName, nil
}

// prepareS4ULogonStructure creates the appropriate S4U logon structure
func prepareS4ULogonStructure(logger *log.Entry, username, domain string, isDomainUser bool) (unsafe.Pointer, uintptr, error) {
	if isDomainUser {
		return prepareDomainS4ULogon(logger, username, domain)
	}
	return prepareLocalS4ULogon(logger, username)
}

// prepareDomainS4ULogon creates S4U logon structure for domain users
func prepareDomainS4ULogon(logger *log.Entry, username, domain string) (unsafe.Pointer, uintptr, error) {
	upn, err := lookupPrincipalName(username, domain)
	if err != nil {
		return nil, 0, fmt.Errorf("lookup principal name: %w", err)
	}

	logger.Debugf("using KerbS4ULogon for domain user with UPN: %s", upn)

	upnUtf16, err := windows.UTF16FromString(upn)
	if err != nil {
		return nil, 0, fmt.Errorf(convertUsernameError, err)
	}

	structSize := unsafe.Sizeof(kerbS4ULogon{})
	upnByteSize := len(upnUtf16) * 2
	logonInfoSize := structSize + uintptr(upnByteSize)

	buffer := make([]byte, logonInfoSize)
	logonInfo := unsafe.Pointer(&buffer[0])

	s4uLogon := (*kerbS4ULogon)(logonInfo)
	s4uLogon.MessageType = KerbS4ULogonType
	s4uLogon.Flags = 0

	upnOffset := structSize
	upnBuffer := (*uint16)(unsafe.Pointer(uintptr(logonInfo) + upnOffset))
	copy((*[1025]uint16)(unsafe.Pointer(upnBuffer))[:len(upnUtf16)], upnUtf16)

	s4uLogon.ClientUpn = unicodeString{
		Length:        uint16((len(upnUtf16) - 1) * 2),
		MaximumLength: uint16(len(upnUtf16) * 2),
		Buffer:        upnBuffer,
	}
	s4uLogon.ClientRealm = unicodeString{}

	return logonInfo, logonInfoSize, nil
}

// prepareLocalS4ULogon creates S4U logon structure for local users
func prepareLocalS4ULogon(logger *log.Entry, username string) (unsafe.Pointer, uintptr, error) {
	logger.Debugf("using Msv1_0S4ULogon for local user: %s", username)

	usernameUtf16, err := windows.UTF16FromString(username)
	if err != nil {
		return nil, 0, fmt.Errorf(convertUsernameError, err)
	}

	domainUtf16, err := windows.UTF16FromString(".")
	if err != nil {
		return nil, 0, fmt.Errorf(convertDomainError, err)
	}

	structSize := unsafe.Sizeof(msv10s4ulogon{})
	usernameByteSize := len(usernameUtf16) * 2
	domainByteSize := len(domainUtf16) * 2
	logonInfoSize := structSize + uintptr(usernameByteSize) + uintptr(domainByteSize)

	buffer := make([]byte, logonInfoSize)
	logonInfo := unsafe.Pointer(&buffer[0])

	s4uLogon := (*msv10s4ulogon)(logonInfo)
	s4uLogon.MessageType = Msv10s4ulogontype
	s4uLogon.Flags = 0x0

	usernameOffset := structSize
	usernameBuffer := (*uint16)(unsafe.Pointer(uintptr(logonInfo) + usernameOffset))
	copy((*[256]uint16)(unsafe.Pointer(usernameBuffer))[:len(usernameUtf16)], usernameUtf16)

	s4uLogon.UserPrincipalName = unicodeString{
		Length:        uint16((len(usernameUtf16) - 1) * 2),
		MaximumLength: uint16(len(usernameUtf16) * 2),
		Buffer:        usernameBuffer,
	}

	domainOffset := usernameOffset + uintptr(usernameByteSize)
	domainBuffer := (*uint16)(unsafe.Pointer(uintptr(logonInfo) + domainOffset))
	copy((*[16]uint16)(unsafe.Pointer(domainBuffer))[:len(domainUtf16)], domainUtf16)

	s4uLogon.DomainName = unicodeString{
		Length:        uint16((len(domainUtf16) - 1) * 2),
		MaximumLength: uint16(len(domainUtf16) * 2),
		Buffer:        domainBuffer,
	}

	return logonInfo, logonInfoSize, nil
}

// performS4ULogon executes the S4U logon operation
func performS4ULogon(logger *log.Entry, lsaHandle windows.Handle, authPackageId uint32, logonInfo unsafe.Pointer, logonInfoSize uintptr, userCpn string, isDomainUser bool) (windows.Handle, error) {
	var tokenSource tokenSource
	copy(tokenSource.SourceName[:], "netbird")
	if ret, _, _ := procAllocateLocallyUniqueId.Call(uintptr(unsafe.Pointer(&tokenSource.SourceIdentifier))); ret == 0 {
		logger.Debugf("AllocateLocallyUniqueId failed")
	}

	originName := newLsaString("netbird")

	var profile uintptr
	var profileSize uint32
	var logonId windows.LUID
	var token windows.Handle
	var quotas quotaLimits
	var subStatus int32

	ret, _, _ := procLsaLogonUser.Call(
		uintptr(lsaHandle),
		uintptr(unsafe.Pointer(&originName)),
		logon32LogonNetwork,
		uintptr(authPackageId),
		uintptr(logonInfo),
		logonInfoSize,
		0,
		uintptr(unsafe.Pointer(&tokenSource)),
		uintptr(unsafe.Pointer(&profile)),
		uintptr(unsafe.Pointer(&profileSize)),
		uintptr(unsafe.Pointer(&logonId)),
		uintptr(unsafe.Pointer(&token)),
		uintptr(unsafe.Pointer(&quotas)),
		uintptr(unsafe.Pointer(&subStatus)),
	)

	if profile != 0 {
		if ret, _, _ := procLsaFreeReturnBuffer.Call(profile); ret != StatusSuccess {
			logger.Debugf("LsaFreeReturnBuffer failed: 0x%x", ret)
		}
	}

	if ret != StatusSuccess {
		return 0, fmt.Errorf("LsaLogonUser S4U for %s: NTSTATUS=0x%x, SubStatus=0x%x", userCpn, ret, subStatus)
	}

	logger.Debugf("created S4U %s token for user %s",
		map[bool]string{true: "domain", false: "local"}[isDomainUser], userCpn)
	return token, nil
}

// createToken implements NetBird trust-based authentication using S4U
func (pd *PrivilegeDropper) createToken(username, domain string) (windows.Handle, error) {
	fullUsername := buildUserCpn(username, domain)

	if err := userExists(fullUsername, username, domain); err != nil {
		return 0, err
	}

	isLocalUser := pd.isLocalUser(domain)

	if isLocalUser {
		return pd.authenticateLocalUser(username, fullUsername)
	}
	return pd.authenticateDomainUser(username, domain, fullUsername)
}

// userExists checks if the target useVerifier exists on the system
func userExists(fullUsername, username, domain string) error {
	if _, err := lookupUser(fullUsername); err != nil {
		log.Debugf("User %s not found: %v", fullUsername, err)
		if domain != "" && domain != "." {
			_, err = lookupUser(username)
		}
		if err != nil {
			return fmt.Errorf("target user %s not found: %w", fullUsername, err)
		}
	}
	return nil
}

// isLocalUser determines if this is a local user vs domain user
func (pd *PrivilegeDropper) isLocalUser(domain string) bool {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}

	return domain == "" || domain == "." ||
		strings.EqualFold(domain, hostname)
}

// authenticateLocalUser handles authentication for local users
func (pd *PrivilegeDropper) authenticateLocalUser(username, fullUsername string) (windows.Handle, error) {
	pd.log().Debugf("using S4U authentication for local user %s", fullUsername)
	token, err := generateS4UUserToken(pd.log(), username, ".")
	if err != nil {
		return 0, fmt.Errorf("S4U authentication for local user %s: %w", fullUsername, err)
	}
	return token, nil
}

// authenticateDomainUser handles authentication for domain users
func (pd *PrivilegeDropper) authenticateDomainUser(username, domain, fullUsername string) (windows.Handle, error) {
	pd.log().Debugf("using S4U authentication for domain user %s", fullUsername)
	token, err := generateS4UUserToken(pd.log(), username, domain)
	if err != nil {
		return 0, fmt.Errorf("S4U authentication for domain user %s: %w", fullUsername, err)
	}
	pd.log().Debugf("successfully created S4U token for domain user %s", fullUsername)
	return token, nil
}

// CreateWindowsProcessAsUser creates a process as user with safe argument passing (for SFTP and executables).
// The caller must close the returned token handle after starting the process.
func (pd *PrivilegeDropper) CreateWindowsProcessAsUser(ctx context.Context, executablePath string, args []string, username, domain, workingDir string) (*exec.Cmd, windows.Token, error) {
	token, err := pd.createToken(username, domain)
	if err != nil {
		return nil, 0, fmt.Errorf("user authentication: %w", err)
	}

	defer func() {
		if err := windows.CloseHandle(token); err != nil {
			pd.log().Debugf("close impersonation token: %v", err)
		}
	}()

	cmd, primaryToken, err := pd.createProcessWithToken(ctx, windows.Token(token), executablePath, args, workingDir)
	if err != nil {
		return nil, 0, err
	}

	return cmd, primaryToken, nil
}

// createProcessWithToken creates process with the specified token and executable path.
// The caller must close the returned token handle after starting the process.
func (pd *PrivilegeDropper) createProcessWithToken(ctx context.Context, sourceToken windows.Token, executablePath string, args []string, workingDir string) (*exec.Cmd, windows.Token, error) {
	cmd := exec.CommandContext(ctx, executablePath, args[1:]...)
	cmd.Dir = workingDir

	var primaryToken windows.Token
	err := windows.DuplicateTokenEx(
		sourceToken,
		windows.TOKEN_ALL_ACCESS,
		nil,
		windows.SecurityIdentification,
		windows.TokenPrimary,
		&primaryToken,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("duplicate token to primary token: %w", err)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token: syscall.Token(primaryToken),
	}

	return cmd, primaryToken, nil
}

// createSuCommand creates a command using su - for privilege switching (Windows stub).
func (s *Server) createSuCommand(*log.Entry, ssh.Session, *user.User, bool) (*exec.Cmd, error) {
	return nil, fmt.Errorf("su command not available on Windows")
}
