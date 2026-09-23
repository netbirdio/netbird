package certproof

import (
	"fmt"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	noActiveSession = 0xFFFFFFFF

	// wtsCurrentServer is WTS_CURRENT_SERVER_HANDLE and wtsActive is WTSActive of
	// WTS_CONNECTSTATE_CLASS. Neither is exported by x/sys/windows.
	wtsCurrentServer = windows.Handle(0)
	wtsActive        = 0
)

// DesktopUser is an interactive session and the account signed into it. The user's
// certificate store is readable only from a process running as that account, because
// its private keys are protected against the user profile rather than the machine.
type DesktopUser struct {
	Session uint32
	Name    string
	Token   windows.Token
}

// Close releases the session token.
func (u DesktopUser) Close() {
	if err := u.Token.Close(); err != nil {
		log.Debugf("failed closing desktop session token: %v", err)
	}
}

// CurrentDesktopUser returns a token for the interactive user whose certificate store
// should be asked. The physical console comes first, and an active remote desktop
// session is used when nobody is at the console, which is how servers and VDI hosts are
// normally reached. The second return is false at the sign-in screen, where no
// interactive session exists and only machine certificates can be proven.
//
// Obtaining the token needs SE_TCB_NAME, which the LocalSystem service has and an
// ordinary process does not.
func CurrentDesktopUser() (DesktopUser, bool) {
	if session := windows.WTSGetActiveConsoleSessionId(); session != noActiveSession {
		if user, ok := desktopUser(session); ok {
			return user, true
		}
		log.Infof("console session %d has nobody signed in, looking for an active remote session", session)
	}

	sessions, err := activeSessions()
	if err != nil {
		log.Infof("cannot enumerate terminal sessions: %v", err)
		return DesktopUser{}, false
	}
	for _, session := range sessions {
		if user, ok := desktopUser(session); ok {
			return user, true
		}
	}

	log.Info("no interactive session is signed in, no user certificate store is reachable")
	return DesktopUser{}, false
}

func desktopUser(session uint32) (DesktopUser, bool) {
	var token windows.Token
	if err := windows.WTSQueryUserToken(session, &token); err != nil {
		log.Debugf("no user token for session %d: %v", session, err)
		return DesktopUser{}, false
	}

	name, err := tokenAccount(token)
	if err != nil {
		log.Infof("session %d token has no readable account: %v", session, err)
		if closeErr := token.Close(); closeErr != nil {
			log.Debugf("failed closing session token: %v", closeErr)
		}
		return DesktopUser{}, false
	}
	return DesktopUser{Session: session, Name: name, Token: token}, true
}

func tokenAccount(token windows.Token) (string, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read token user: %w", err)
	}
	account, domain, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		return "", fmt.Errorf("look up account: %w", err)
	}
	if domain == "" {
		return account, nil
	}
	return domain + `\` + account, nil
}

func activeSessions() ([]uint32, error) {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(wtsCurrentServer, 0, 1, &info, &count); err != nil {
		return nil, fmt.Errorf("enumerate sessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))

	var active []uint32
	for _, session := range unsafe.Slice(info, count) {
		if session.State == wtsActive {
			active = append(active, session.SessionID)
		}
	}
	return active, nil
}

// runningAsLocalSystem reports whether this process is the service. The helper runs as
// the signed-in user and must read its own store rather than launching another helper.
func runningAsLocalSystem() bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		log.Debugf("failed reading own token user: %v", err)
		return false
	}
	return user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}
