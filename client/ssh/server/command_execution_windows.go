package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/netbirdio/netbird/client/ssh/server/winpty"
)

// getUserEnvironment retrieves the Windows environment for the target user.
// Follows OpenSSH's resilient approach with graceful degradation on failures.
func (s *Server) getUserEnvironment(logger *log.Entry, username, domain string) ([]string, error) {
	userToken, err := s.getUserToken(logger, username, domain)
	if err != nil {
		return nil, fmt.Errorf("get user token: %w", err)
	}
	defer func() {
		if err := windows.CloseHandle(userToken); err != nil {
			logger.Debugf("close user token: %v", err)
		}
	}()

	return s.getUserEnvironmentWithToken(logger, userToken, username, domain)
}

// getUserEnvironmentWithToken retrieves the Windows environment using an existing token.
func (s *Server) getUserEnvironmentWithToken(logger *log.Entry, userToken windows.Handle, username, domain string) ([]string, error) {
	userProfile, err := s.loadUserProfile(userToken, username, domain)
	if err != nil {
		logger.Debugf("failed to load user profile for %s\\%s: %v", domain, username, err)
		userProfile = fmt.Sprintf("C:\\Users\\%s", username)
	}

	envMap := make(map[string]string)

	if err := s.loadSystemEnvironment(envMap); err != nil {
		logger.Debugf("failed to load system environment from registry: %v", err)
	}

	s.setUserEnvironmentVariables(envMap, userProfile, username, domain)

	var env []string
	for key, value := range envMap {
		env = append(env, key+"="+value)
	}

	return env, nil
}

// getUserToken creates a user token for the specified user.
func (s *Server) getUserToken(logger *log.Entry, username, domain string) (windows.Handle, error) {
	privilegeDropper := NewPrivilegeDropper(WithLogger(logger))
	token, err := privilegeDropper.createToken(username, domain)
	if err != nil {
		return 0, fmt.Errorf("generate S4U user token: %w", err)
	}
	return token, nil
}

// loadUserProfile loads the Windows user profile and returns the profile path.
func (s *Server) loadUserProfile(userToken windows.Handle, username, domain string) (string, error) {
	usernamePtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return "", fmt.Errorf("convert username to UTF-16: %w", err)
	}

	var domainUTF16 *uint16
	if domain != "" && domain != "." {
		domainUTF16, err = windows.UTF16PtrFromString(domain)
		if err != nil {
			return "", fmt.Errorf("convert domain to UTF-16: %w", err)
		}
	}

	type profileInfo struct {
		dwSize        uint32
		dwFlags       uint32
		lpUserName    *uint16
		lpProfilePath *uint16
		lpDefaultPath *uint16
		lpServerName  *uint16
		lpPolicyPath  *uint16
		hProfile      windows.Handle
	}

	const PI_NOUI = 0x00000001

	profile := profileInfo{
		dwSize:       uint32(unsafe.Sizeof(profileInfo{})),
		dwFlags:      PI_NOUI,
		lpUserName:   usernamePtr,
		lpServerName: domainUTF16,
	}

	userenv := windows.NewLazySystemDLL("userenv.dll")
	loadUserProfileW := userenv.NewProc("LoadUserProfileW")

	ret, _, err := loadUserProfileW.Call(
		uintptr(userToken),
		uintptr(unsafe.Pointer(&profile)),
	)

	if ret == 0 {
		return "", fmt.Errorf("LoadUserProfileW: %w", err)
	}

	if profile.lpProfilePath == nil {
		return "", fmt.Errorf("LoadUserProfileW returned null profile path")
	}

	profilePath := windows.UTF16PtrToString(profile.lpProfilePath)
	return profilePath, nil
}

// loadSystemEnvironment loads system-wide environment variables from registry.
func (s *Server) loadSystemEnvironment(envMap map[string]string) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`,
		registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("open system environment registry key: %w", err)
	}
	defer func() {
		if err := key.Close(); err != nil {
			log.Debugf("close registry key: %v", err)
		}
	}()

	return s.readRegistryEnvironment(key, envMap)
}

// readRegistryEnvironment reads environment variables from a registry key.
func (s *Server) readRegistryEnvironment(key registry.Key, envMap map[string]string) error {
	names, err := key.ReadValueNames(0)
	if err != nil {
		return fmt.Errorf("read registry value names: %w", err)
	}

	for _, name := range names {
		value, valueType, err := key.GetStringValue(name)
		if err != nil {
			log.Debugf("failed to read registry value %s: %v", name, err)
			continue
		}

		finalValue := s.expandRegistryValue(value, valueType, name)
		s.setEnvironmentVariable(envMap, name, finalValue)
	}

	return nil
}

// expandRegistryValue expands registry values if they contain environment variables.
func (s *Server) expandRegistryValue(value string, valueType uint32, name string) string {
	if valueType != registry.EXPAND_SZ {
		return value
	}

	sourcePtr := windows.StringToUTF16Ptr(value)
	expandedBuffer := make([]uint16, 1024)
	expandedLen, err := windows.ExpandEnvironmentStrings(sourcePtr, &expandedBuffer[0], uint32(len(expandedBuffer)))
	if err != nil {
		log.Debugf("failed to expand environment string for %s: %v", name, err)
		return value
	}

	// If buffer was too small, retry with larger buffer
	if expandedLen > uint32(len(expandedBuffer)) {
		expandedBuffer = make([]uint16, expandedLen)
		expandedLen, err = windows.ExpandEnvironmentStrings(sourcePtr, &expandedBuffer[0], uint32(len(expandedBuffer)))
		if err != nil {
			log.Debugf("failed to expand environment string for %s on retry: %v", name, err)
			return value
		}
	}

	if expandedLen > 0 && expandedLen <= uint32(len(expandedBuffer)) {
		return windows.UTF16ToString(expandedBuffer[:expandedLen-1])
	}
	return value
}

// setEnvironmentVariable sets an environment variable with special handling for PATH.
func (s *Server) setEnvironmentVariable(envMap map[string]string, name, value string) {
	upperName := strings.ToUpper(name)

	if upperName == "PATH" {
		if existing, exists := envMap["PATH"]; exists && existing != value {
			envMap["PATH"] = existing + ";" + value
		} else {
			envMap["PATH"] = value
		}
	} else {
		envMap[upperName] = value
	}
}

// setUserEnvironmentVariables sets critical user-specific environment variables.
func (s *Server) setUserEnvironmentVariables(envMap map[string]string, userProfile, username, domain string) {
	envMap["USERPROFILE"] = userProfile

	if len(userProfile) >= 2 && userProfile[1] == ':' {
		envMap["HOMEDRIVE"] = userProfile[:2]
		envMap["HOMEPATH"] = userProfile[2:]
	}

	envMap["APPDATA"] = filepath.Join(userProfile, "AppData", "Roaming")
	envMap["LOCALAPPDATA"] = filepath.Join(userProfile, "AppData", "Local")

	tempDir := filepath.Join(userProfile, "AppData", "Local", "Temp")
	envMap["TEMP"] = tempDir
	envMap["TMP"] = tempDir

	envMap["USERNAME"] = username
	if domain != "" && domain != "." {
		envMap["USERDOMAIN"] = domain
		envMap["USERDNSDOMAIN"] = domain
	}

	systemVars := []string{
		"PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL", "PROCESSOR_REVISION",
		"SYSTEMDRIVE", "SYSTEMROOT", "WINDIR", "COMPUTERNAME", "OS", "PATHEXT",
		"PROGRAMFILES", "PROGRAMDATA", "ALLUSERSPROFILE", "COMSPEC",
	}

	for _, sysVar := range systemVars {
		if sysValue := os.Getenv(sysVar); sysValue != "" {
			envMap[sysVar] = sysValue
		}
	}
}

// prepareCommandEnv prepares environment variables for command execution on Windows
func (s *Server) prepareCommandEnv(logger *log.Entry, localUser *user.User, session ssh.Session) []string {
	username, domain := s.parseUsername(localUser.Username)
	userEnv, err := s.getUserEnvironment(logger, username, domain)
	if err != nil {
		log.Debugf("failed to get user environment for %s\\%s, using fallback: %v", domain, username, err)
		env := prepareUserEnv(localUser, getUserShell(localUser.Uid))
		env = append(env, prepareSSHEnv(session)...)
		for _, v := range session.Environ() {
			if acceptEnv(v) {
				env = append(env, v)
			}
		}
		return env
	}

	env := userEnv
	env = append(env, prepareSSHEnv(session)...)
	for _, v := range session.Environ() {
		if acceptEnv(v) {
			env = append(env, v)
		}
	}
	return env
}

func (s *Server) handlePtyLogin(logger *log.Entry, session ssh.Session, privilegeResult PrivilegeCheckResult, ptyReq ssh.Pty, _ <-chan ssh.Window) bool {
	if privilegeResult.User == nil {
		logger.Errorf("no user in privilege result")
		return false
	}

	shell := getUserShell(privilegeResult.User.Uid)
	logger.Infof("starting interactive shell: %s", shell)

	s.executeCommandWithPty(logger, session, nil, privilegeResult, ptyReq, nil)
	return true
}

// getShellCommandArgs returns the shell command and arguments for executing a command string
func (s *Server) getShellCommandArgs(shell, cmdString string) []string {
	if cmdString == "" {
		return []string{shell, "-NoLogo"}
	}
	return []string{shell, "-Command", cmdString}
}

type PtyExecutionRequest struct {
	Shell    string
	Command  string
	Width    int
	Height   int
	Username string
	Domain   string
}

func executePtyCommandWithUserToken(logger *log.Entry, session ssh.Session, req PtyExecutionRequest) error {
	logger.Tracef("executing Windows ConPty command with user switching: shell=%s, command=%s, user=%s\\%s, size=%dx%d",
		req.Shell, req.Command, req.Domain, req.Username, req.Width, req.Height)

	privilegeDropper := NewPrivilegeDropper(WithLogger(logger))
	userToken, err := privilegeDropper.createToken(req.Username, req.Domain)
	if err != nil {
		return fmt.Errorf("create user token: %w", err)
	}
	defer func() {
		if err := windows.CloseHandle(userToken); err != nil {
			logger.Debugf("close user token: %v", err)
		}
	}()

	server := &Server{}
	userEnv, err := server.getUserEnvironmentWithToken(logger, userToken, req.Username, req.Domain)
	if err != nil {
		logger.Debugf("failed to get user environment for %s\\%s, using system environment: %v", req.Domain, req.Username, err)
		userEnv = os.Environ()
	}

	workingDir := getUserHomeFromEnv(userEnv)
	if workingDir == "" {
		workingDir = fmt.Sprintf(`C:\Users\%s`, req.Username)
	}

	ptyConfig := winpty.PtyConfig{
		Shell:      req.Shell,
		Command:    req.Command,
		Width:      req.Width,
		Height:     req.Height,
		WorkingDir: workingDir,
	}

	userConfig := winpty.UserConfig{
		Token:       userToken,
		Environment: userEnv,
	}

	logger.Debugf("executePtyCommandWithUserToken: calling winpty execution with working dir: %s", workingDir)
	return winpty.ExecutePtyWithUserToken(session, ptyConfig, userConfig)
}

func getUserHomeFromEnv(env []string) string {
	for _, envVar := range env {
		if len(envVar) > 12 && envVar[:12] == "USERPROFILE=" {
			return envVar[12:]
		}
	}
	return ""
}

func (s *Server) setupProcessGroup(_ *exec.Cmd) {
	// Windows doesn't support process groups in the same way as Unix
	// Process creation groups are handled differently
}

func (s *Server) killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}

	if err := cmd.Process.Kill(); err != nil {
		log.Debugf("kill process %d failed: %v", cmd.Process.Pid, err)
	}
}

// detectSuPtySupport always returns false on Windows as su is not available
func (s *Server) detectSuPtySupport(context.Context) bool {
	return false
}

// detectUtilLinuxLogin always returns false on Windows
func (s *Server) detectUtilLinuxLogin(context.Context) bool {
	return false
}

// executeCommandWithPty executes a command with PTY allocation on Windows using ConPty
func (s *Server) executeCommandWithPty(logger *log.Entry, session ssh.Session, _ *exec.Cmd, privilegeResult PrivilegeCheckResult, ptyReq ssh.Pty, _ <-chan ssh.Window) bool {
	localUser := privilegeResult.User
	if localUser == nil {
		logger.Errorf("no user in privilege result")
		return false
	}

	username, domain := s.parseUsername(localUser.Username)
	shell := getUserShell(localUser.Uid)

	req := PtyExecutionRequest{
		Shell:    shell,
		Command:  session.RawCommand(),
		Width:    ptyReq.Window.Width,
		Height:   ptyReq.Window.Height,
		Username: username,
		Domain:   domain,
	}

	if err := executePtyCommandWithUserToken(logger, session, req); err != nil {
		logger.Errorf("ConPty execution failed: %v", err)
		if err := session.Exit(1); err != nil {
			logSessionExitError(logger, err)
		}
		return false
	}

	logger.Debug("ConPty execution completed")
	return true
}
