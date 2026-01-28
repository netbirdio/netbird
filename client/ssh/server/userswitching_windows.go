//go:build windows

package server

import (
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"strings"
	"unsafe"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// validateUsername validates Windows usernames according to SAM Account Name rules
func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	usernameToValidate := extractUsernameFromDomain(username)

	if err := validateUsernameLength(usernameToValidate); err != nil {
		return err
	}

	if err := validateUsernameCharacters(usernameToValidate); err != nil {
		return err
	}

	if err := validateUsernameFormat(usernameToValidate); err != nil {
		return err
	}

	return nil
}

// extractUsernameFromDomain extracts the username part from domain\username or username@domain format
func extractUsernameFromDomain(username string) string {
	if idx := strings.LastIndex(username, `\`); idx != -1 {
		return username[idx+1:]
	}
	if idx := strings.Index(username, "@"); idx != -1 {
		return username[:idx]
	}
	return username
}

// validateUsernameLength checks if username length is within Windows limits
func validateUsernameLength(username string) error {
	if len(username) > 20 {
		return fmt.Errorf("username too long (max 20 characters for Windows)")
	}
	return nil
}

// validateUsernameCharacters checks for invalid characters in Windows usernames
func validateUsernameCharacters(username string) error {
	invalidChars := []rune{'"', '/', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', ' ', '`', '&', '\n'}
	for _, char := range username {
		for _, invalid := range invalidChars {
			if char == invalid {
				return fmt.Errorf("username contains invalid characters")
			}
		}
		if char < 32 || char == 127 {
			return fmt.Errorf("username contains control characters")
		}
	}
	return nil
}

// validateUsernameFormat checks for invalid username formats and patterns
func validateUsernameFormat(username string) error {
	if username == "." || username == ".." {
		return fmt.Errorf("username cannot be '.' or '..'")
	}

	if strings.HasSuffix(username, ".") {
		return fmt.Errorf("username cannot end with a period")
	}

	return nil
}

// createExecutorCommand creates a command using Windows executor for privilege dropping.
// Returns the command and a cleanup function that must be called after starting the process.
func (s *Server) createExecutorCommand(logger *log.Entry, session ssh.Session, localUser *user.User, hasPty bool) (*exec.Cmd, func(), error) {
	logger.Debugf("creating Windows executor command for user %s (Pty: %v)", localUser.Username, hasPty)

	username, _ := s.parseUsername(localUser.Username)
	if err := validateUsername(username); err != nil {
		return nil, nil, fmt.Errorf("invalid username %q: %w", username, err)
	}

	return s.createUserSwitchCommand(logger, session, localUser)
}

// createUserSwitchCommand creates a command with Windows user switching.
// Returns the command and a cleanup function that must be called after starting the process.
func (s *Server) createUserSwitchCommand(logger *log.Entry, session ssh.Session, localUser *user.User) (*exec.Cmd, func(), error) {
	username, domain := s.parseUsername(localUser.Username)

	shell := getUserShell(localUser.Uid)

	rawCmd := session.RawCommand()
	var command string
	if rawCmd != "" {
		command = rawCmd
	}

	config := WindowsExecutorConfig{
		Username:   username,
		Domain:     domain,
		WorkingDir: localUser.HomeDir,
		Shell:      shell,
		Command:    command,
	}

	dropper := NewPrivilegeDropper(WithLogger(logger))
	cmd, token, err := dropper.CreateWindowsExecutorCommand(session.Context(), config)
	if err != nil {
		return nil, nil, err
	}

	cleanup := func() {
		if token != 0 {
			if err := windows.CloseHandle(windows.Handle(token)); err != nil {
				logger.Debugf("close primary token: %v", err)
			}
		}
	}

	return cmd, cleanup, nil
}

// parseUsername extracts username and domain from a Windows username
func (s *Server) parseUsername(fullUsername string) (username, domain string) {
	// Handle DOMAIN\username format
	if idx := strings.LastIndex(fullUsername, `\`); idx != -1 {
		domain = fullUsername[:idx]
		username = fullUsername[idx+1:]
		return username, domain
	}

	// Handle username@domain format
	if username, domain, ok := strings.Cut(fullUsername, "@"); ok {
		return username, domain
	}

	// Local user (no domain)
	return fullUsername, "."
}

// hasPrivilege checks if the current process has a specific privilege
func hasPrivilege(token windows.Handle, privilegeName string) (bool, error) {
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(privilegeName), &luid); err != nil {
		return false, fmt.Errorf("lookup privilege value: %w", err)
	}

	var returnLength uint32
	err := windows.GetTokenInformation(
		windows.Token(token),
		windows.TokenPrivileges,
		nil, // null buffer to get size
		0,
		&returnLength,
	)

	if err != nil && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return false, fmt.Errorf("get token information size: %w", err)
	}

	buffer := make([]byte, returnLength)
	err = windows.GetTokenInformation(
		windows.Token(token),
		windows.TokenPrivileges,
		&buffer[0],
		returnLength,
		&returnLength,
	)
	if err != nil {
		return false, fmt.Errorf("get token information: %w", err)
	}

	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0]))

	// Check if the privilege is present and enabled
	for i := uint32(0); i < privileges.PrivilegeCount; i++ {
		privilege := (*windows.LUIDAndAttributes)(unsafe.Pointer(
			uintptr(unsafe.Pointer(&privileges.Privileges[0])) +
				uintptr(i)*unsafe.Sizeof(windows.LUIDAndAttributes{}),
		))
		if privilege.Luid == luid {
			return (privilege.Attributes & windows.SE_PRIVILEGE_ENABLED) != 0, nil
		}
	}

	return false, nil
}

// enablePrivilege enables a specific privilege for the current process token
// This is required because privileges like SeAssignPrimaryTokenPrivilege are present
// but disabled by default, even for the SYSTEM account
func enablePrivilege(token windows.Handle, privilegeName string) error {
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(privilegeName), &luid); err != nil {
		return fmt.Errorf("lookup privilege value for %s: %w", privilegeName, err)
	}

	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	err := windows.AdjustTokenPrivileges(
		windows.Token(token),
		false,
		&privileges,
		0,
		nil,
		nil,
	)
	if err != nil {
		return fmt.Errorf("adjust token privileges for %s: %w", privilegeName, err)
	}

	hasPriv, err := hasPrivilege(token, privilegeName)
	if err != nil {
		return fmt.Errorf("verify privilege %s after enabling: %w", privilegeName, err)
	}
	if !hasPriv {
		return fmt.Errorf("privilege %s could not be enabled (may not be granted to account)", privilegeName)
	}

	log.Debugf("Successfully enabled privilege %s for current process", privilegeName)
	return nil
}

// enableUserSwitching enables required privileges for Windows user switching
func enableUserSwitching() error {
	process := windows.CurrentProcess()

	var token windows.Token
	err := windows.OpenProcessToken(
		process,
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&token,
	)
	if err != nil {
		return fmt.Errorf("open process token: %w", err)
	}
	defer func() {
		if err := windows.CloseHandle(windows.Handle(token)); err != nil {
			log.Debugf("Failed to close process token: %v", err)
		}
	}()

	if err := enablePrivilege(windows.Handle(token), "SeAssignPrimaryTokenPrivilege"); err != nil {
		return fmt.Errorf("enable SeAssignPrimaryTokenPrivilege: %w", err)
	}
	log.Infof("Windows user switching privileges enabled successfully")
	return nil
}
