package certproof

import (
	"fmt"
	"strings"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	noActiveSession = 0xFFFFFFFF
	servicesSession = 0

	// wtsCurrentServer is WTS_CURRENT_SERVER_HANDLE; wtsActive and wtsDisconnected are
	// WTSActive and WTSDisconnected of WTS_CONNECTSTATE_CLASS. None is exported by
	// x/sys/windows.
	wtsCurrentServer = windows.Handle(0)
	wtsActive        = 0
	wtsDisconnected  = 4
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

// CurrentDesktopUser returns a token for the session whose certificate store should be
// asked: a session of owner, the account the active profile belongs to, with the
// physical console preferred over remote sessions. With no owner only the console user
// counts. Picking any signed-in user instead would let whoever else is logged in to a
// terminal server or VDI host decide the result. The second return is false when no
// such session exists, and only machine certificates can then be proven.
//
// Obtaining the token needs SE_TCB_NAME, which the LocalSystem service has and an
// ordinary process does not.
func CurrentDesktopUser(owner string) (DesktopUser, bool) {
	console := windows.WTSGetActiveConsoleSessionId()
	if owner == "" {
		return consoleUser(console)
	}

	sessions, err := userSessions(console)
	if err != nil {
		log.Debugf("cannot enumerate terminal sessions: %v", err)
		return DesktopUser{}, false
	}
	for _, session := range sessions {
		user, ok := desktopUser(session)
		if !ok {
			continue
		}
		if sameAccountName(user.Name, owner) {
			return user, true
		}
		user.Close()
	}

	log.Debugf("certificate posture: profile owner %s has no signed-in session, no user certificate store is reachable", owner)
	return DesktopUser{}, false
}

func consoleUser(console uint32) (DesktopUser, bool) {
	if console == noActiveSession || console == servicesSession {
		log.Debug("no console session, no user certificate store is reachable")
		return DesktopUser{}, false
	}
	user, ok := desktopUser(console)
	if !ok {
		log.Debugf("console session %d has nobody signed in, no user certificate store is reachable", console)
	}
	return user, ok
}

// sameAccountName compares DOMAIN\account names case-insensitively, as Windows does, and an
// owner given without a domain against the account part alone. The session side comes from
// the session token's own SID, which Windows resolves from its cache of signed-in users.
// Resolving the owner name to a SID instead would ask the domain controller, which on a
// laptop that cannot reach it yet blocks for tens of seconds, past the collection deadline.
func sameAccountName(sessionName, owner string) bool {
	if strings.EqualFold(sessionName, owner) {
		return true
	}
	if strings.Contains(owner, `\`) {
		return false
	}
	_, account, found := strings.Cut(sessionName, `\`)
	return found && strings.EqualFold(account, owner)
}

func desktopUser(session uint32) (DesktopUser, bool) {
	var token windows.Token
	if err := windows.WTSQueryUserToken(session, &token); err != nil {
		log.Debugf("no user token for session %d: %v", session, err)
		return DesktopUser{}, false
	}

	name, err := tokenAccount(token)
	if err != nil {
		log.Debugf("session %d token has no readable account: %v", session, err)
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

// userSessions lists the sessions a user can be signed in to, console first, then
// active remote sessions, then disconnected ones, whose user is still signed in. Session
// 0 is skipped: it hosts services and never belongs to an interactive user.
func userSessions(console uint32) ([]uint32, error) {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(wtsCurrentServer, 0, 1, &info, &count); err != nil {
		return nil, fmt.Errorf("enumerate sessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))

	var sessions []uint32
	if console != noActiveSession && console != servicesSession {
		sessions = append(sessions, console)
	}
	for _, state := range []uint32{wtsActive, wtsDisconnected} {
		for _, session := range unsafe.Slice(info, count) {
			if session.SessionID == servicesSession || session.SessionID == console || session.State != state {
				continue
			}
			sessions = append(sessions, session.SessionID)
		}
	}
	return sessions, nil
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
