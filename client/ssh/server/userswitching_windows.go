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

	// Handle domain\username format - extract just the username part for validation
	usernameToValidate := username
	if idx := strings.LastIndex(username, `\`); idx != -1 {
		usernameToValidate = username[idx+1:]
	}

	// Windows SAM Account Name limits: 20 characters for users, 16 for computers
	// We use 20 as the general limit (applies to username part only)
	if len(usernameToValidate) > 20 {
		return fmt.Errorf("username too long (max 20 characters for Windows)")
	}

	// Check for Windows SAM Account Name invalid characters
	// Prohibited: " / \ [ ] : ; | = , + * ? < >
	// Note: backslash is allowed in full username (domain\user) but not in the user part
	invalidChars := []rune{'"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>'}
	for _, char := range usernameToValidate {
		for _, invalid := range invalidChars {
			if char == invalid {
				return fmt.Errorf("username contains invalid character '%c'", char)
			}
		}
		// Check for control characters (ASCII < 32 or == 127)
		if char < 32 || char == 127 {
			return fmt.Errorf("username contains control characters")
		}
	}

	// Period cannot be the final character
	if strings.HasSuffix(usernameToValidate, ".") {
		return fmt.Errorf("username cannot end with a period")
	}

	// Check for reserved patterns
	if usernameToValidate == "." || usernameToValidate == ".." {
		return fmt.Errorf("username cannot be '.' or '..'")
	}

	// Warn about @ character (causes login issues) - check in username part only
	if strings.Contains(usernameToValidate, "@") {
		log.Warnf("username '%s' contains '@' character which may cause login issues", usernameToValidate)
	}

	return nil
}

// createExecutorCommand creates a command using Windows executor for privilege dropping
func (s *Server) createExecutorCommand(session ssh.Session, localUser *user.User, hasPty bool) (*exec.Cmd, error) {
	log.Debugf("creating Windows executor command for user %s (Pty: %v)", localUser.Username, hasPty)

	username, _ := s.parseUsername(localUser.Username)
	if err := validateUsername(username); err != nil {
		return nil, fmt.Errorf("invalid username: %w", err)
	}

	return s.createUserSwitchCommand(localUser, session, hasPty)
}

// createDirectCommand is not supported on Windows - always use user switching with token creation
func (s *Server) createDirectCommand(session ssh.Session, localUser *user.User) (*exec.Cmd, error) {
	return nil, fmt.Errorf("direct command execution not supported on Windows - use user switching with token creation")
}

// createUserSwitchCommand creates a command with Windows user switching
func (s *Server) createUserSwitchCommand(localUser *user.User, session ssh.Session, interactive bool) (*exec.Cmd, error) {
	username, domain := s.parseUsername(localUser.Username)

	shell := getUserShell(localUser.Uid)

	rawCmd := session.RawCommand()
	var command string
	if rawCmd != "" {
		command = rawCmd
	}

	config := WindowsExecutorConfig{
		Username:    username,
		Domain:      domain,
		WorkingDir:  localUser.HomeDir,
		Shell:       shell,
		Command:     command,
		Interactive: interactive || (rawCmd == ""),
	}

	dropper := NewPrivilegeDropper()
	return dropper.CreateWindowsExecutorCommand(session.Context(), config)
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
