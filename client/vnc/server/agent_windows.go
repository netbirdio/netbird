//go:build windows

package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	stillActive = 259

	tokenPrimary          = 1
	securityImpersonation = 2
	tokenSessionID        = 12

	createUnicodeEnvironment = 0x00000400
	createNoWindow           = 0x08000000
	createSuspended          = 0x00000004
	createBreakawayFromJob   = 0x01000000
)

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")
	userenv  = windows.NewLazySystemDLL("userenv.dll")

	procWTSGetActiveConsoleSessionId = kernel32.NewProc("WTSGetActiveConsoleSessionId")
	procCreateJobObjectW             = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject      = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject     = kernel32.NewProc("AssignProcessToJobObject")
	procSetTokenInformation          = advapi32.NewProc("SetTokenInformation")
	procCreateEnvironmentBlock       = userenv.NewProc("CreateEnvironmentBlock")
	procDestroyEnvironmentBlock      = userenv.NewProc("DestroyEnvironmentBlock")

	wtsapi32                       = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumerateSessionsW      = wtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSFreeMemory              = wtsapi32.NewProc("WTSFreeMemory")
	procWTSQuerySessionInformation = wtsapi32.NewProc("WTSQuerySessionInformationW")

	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
)

// GetCurrentSessionID returns the session ID of the current process.
func GetCurrentSessionID() uint32 {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_QUERY, &token); err != nil {
		return 0
	}
	defer token.Close()
	var id uint32
	var ret uint32
	_ = windows.GetTokenInformation(token, windows.TokenSessionId,
		(*byte)(unsafe.Pointer(&id)), 4, &ret)
	return id
}

func getConsoleSessionID() uint32 {
	r, _, _ := procWTSGetActiveConsoleSessionId.Call()
	return uint32(r)
}

const (
	wtsActive       = 0
	wtsConnected    = 1
	wtsDisconnected = 4
)

// getActiveSessionID returns the session ID of the best session to attach to.
// On a Windows Server with no console display attached, session 1 still
// reports WTSActive (login screen "owns" the console), so a naive
// first-active-wins pick lands on a session with no actual rendering.
// Preference order:
//  1. Active session with a user logged in (RDP user in session ≥2)
//  2. Active session without a user (console at login screen)
//  3. Console session ID
func getActiveSessionID() uint32 {
	var sessionInfo uintptr
	var count uint32

	r, _, _ := procWTSEnumerateSessionsW.Call(
		0, // WTS_CURRENT_SERVER_HANDLE
		0, // reserved
		1, // version
		uintptr(unsafe.Pointer(&sessionInfo)),
		uintptr(unsafe.Pointer(&count)),
	)
	if r == 0 || count == 0 {
		return getConsoleSessionID()
	}
	defer func() { _, _, _ = procWTSFreeMemory.Call(sessionInfo) }()

	type wtsSession struct {
		SessionID uint32
		Station   *uint16
		State     uint32
	}
	sessions := unsafe.Slice((*wtsSession)(unsafe.Pointer(sessionInfo)), count)

	var withUser uint32
	var withUserFound bool
	var anyActive uint32
	var anyActiveFound bool
	for _, s := range sessions {
		if s.SessionID == 0 {
			continue
		}
		if s.State != wtsActive {
			continue
		}
		if !anyActiveFound {
			anyActive = s.SessionID
			anyActiveFound = true
		}
		if !withUserFound && wtsSessionHasUser(s.SessionID) {
			withUser = s.SessionID
			withUserFound = true
		}
	}
	if withUserFound {
		return withUser
	}
	if anyActiveFound {
		return anyActive
	}
	return getConsoleSessionID()
}

// wtsSessionHasUser returns true if the session has a non-empty user name,
// i.e. someone is logged in (vs. the login/Welcome screen). The console
// session at the lock screen has WTSUserName == "".
const wtsUserName = 5

func wtsSessionHasUser(sessionID uint32) bool {
	var buf uintptr
	var bytesReturned uint32
	r, _, _ := procWTSQuerySessionInformation.Call(
		0, // WTS_CURRENT_SERVER_HANDLE
		uintptr(sessionID),
		uintptr(wtsUserName),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if r == 0 || buf == 0 {
		return false
	}
	defer func() { _, _, _ = procWTSFreeMemory.Call(buf) }()
	// First UTF-16 code unit non-zero ⇒ non-empty username.
	return *(*uint16)(unsafe.Pointer(buf)) != 0
}

// getSystemTokenForSession duplicates the current SYSTEM token and sets its
// session ID so the spawned process runs in the target session. Using a SYSTEM
// token gives access to both Default and Winlogon desktops plus UIPI bypass.
func getSystemTokenForSession(sessionID uint32) (windows.Token, error) {
	var cur windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.MAXIMUM_ALLOWED, &cur); err != nil {
		return 0, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer cur.Close()

	var dup windows.Token
	if err := windows.DuplicateTokenEx(cur, windows.MAXIMUM_ALLOWED, nil,
		securityImpersonation, tokenPrimary, &dup); err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", err)
	}

	sid := sessionID
	r, _, err := procSetTokenInformation.Call(
		uintptr(dup),
		uintptr(tokenSessionID),
		uintptr(unsafe.Pointer(&sid)),
		unsafe.Sizeof(sid),
	)
	if r == 0 {
		dup.Close()
		return 0, fmt.Errorf("SetTokenInformation(SessionId=%d): %w", sessionID, err)
	}
	return dup, nil
}

// injectEnvVar appends a KEY=VALUE entry to a Unicode environment block.
// The block is a sequence of null-terminated UTF-16 strings, terminated by
// an extra null. Returns the new []uint16 backing slice; the caller must
// hold the returned slice alive until CreateProcessAsUser completes.
func injectEnvVar(envBlock uintptr, key, value string) []uint16 {
	entry := key + "=" + value

	// Walk the existing block to find its total length.
	ptr := (*uint16)(unsafe.Pointer(envBlock))
	var totalChars int
	for {
		ch := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(totalChars)*2))
		if ch == 0 {
			// Check for double-null terminator.
			next := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(totalChars+1)*2))
			totalChars++
			if next == 0 {
				// End of block (don't count the final null yet, we'll rebuild).
				break
			}
		} else {
			totalChars++
		}
	}

	entryUTF16, _ := windows.UTF16FromString(entry)
	// New block: existing entries + new entry (null-terminated) + final null.
	newLen := totalChars + len(entryUTF16) + 1
	newBlock := make([]uint16, newLen)
	// Copy existing entries (up to but not including the final null).
	for i := range totalChars {
		newBlock[i] = *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i)*2))
	}
	copy(newBlock[totalChars:], entryUTF16)
	newBlock[newLen-1] = 0 // final null terminator

	return newBlock
}

func spawnAgentInSession(sessionID uint32, socketPath, authToken string, jobHandle windows.Handle) (windows.Handle, error) {
	token, err := getSystemTokenForSession(sessionID)
	if err != nil {
		return 0, fmt.Errorf("get SYSTEM token for session %d: %w", sessionID, err)
	}
	defer token.Close()

	var envBlock uintptr
	r, _, e := procCreateEnvironmentBlock.Call(
		uintptr(unsafe.Pointer(&envBlock)),
		uintptr(token),
		0,
	)
	if r == 0 {
		// Without an environment block we cannot inject NB_VNC_AGENT_TOKEN;
		// the agent would start unauthenticated. Abort instead of launching.
		return 0, fmt.Errorf("CreateEnvironmentBlock: %w", e)
	}
	defer func() { _, _, _ = procDestroyEnvironmentBlock.Call(envBlock) }()

	// Inject the auth token into the environment block so it doesn't appear
	// in the process command line (visible via tasklist/wmic). injectedBlock
	// must stay alive until CreateProcessAsUser returns.
	injectedBlock := injectEnvVar(envBlock, agentTokenEnvVar, authToken)

	exePath, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("get executable path: %w", err)
	}

	cmdLine := fmt.Sprintf(`"%s" %s --socket %q`, exePath, vncAgentSubcommand, socketPath)
	cmdLineW, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return 0, fmt.Errorf("UTF16 cmdline: %w", err)
	}

	// Create an inheritable pipe for the agent's stderr so we can relog
	// its output in the service process.
	var sa windows.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.InheritHandle = 1

	var stderrRead, stderrWrite windows.Handle
	if err := windows.CreatePipe(&stderrRead, &stderrWrite, &sa, 0); err != nil {
		return 0, fmt.Errorf("create stderr pipe: %w", err)
	}
	// The read end must NOT be inherited by the child.
	_ = windows.SetHandleInformation(stderrRead, windows.HANDLE_FLAG_INHERIT, 0)

	desktop, _ := windows.UTF16PtrFromString(`WinSta0\Default`)
	si := windows.StartupInfo{
		Cb:         uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Desktop:    desktop,
		Flags:      windows.STARTF_USESHOWWINDOW | windows.STARTF_USESTDHANDLES,
		ShowWindow: 0,
		StdErr:     stderrWrite,
		StdOutput:  stderrWrite,
	}
	var pi windows.ProcessInformation

	var envPtr *uint16
	if len(injectedBlock) > 0 {
		envPtr = &injectedBlock[0]
	} else if envBlock != 0 {
		envPtr = (*uint16)(unsafe.Pointer(envBlock))
	}

	// CREATE_SUSPENDED so we can assign the process to our Job Object
	// before it executes. Without this the agent could spawn its own child
	// processes and have them inherit the SCM service-job (not ours), or
	// briefly listen on the agent port before we tear it down on rollback.
	// CREATE_BREAKAWAY_FROM_JOB lets the child leave the SCM-managed
	// service job; harmless if that job allows breakaway, and is required
	// before AssignProcessToJobObject can succeed in the no-nested-jobs case.
	err = windows.CreateProcessAsUser(
		token, nil, cmdLineW,
		nil, nil, true, // inheritHandles=true for the pipe
		createUnicodeEnvironment|createNoWindow|createSuspended|createBreakawayFromJob,
		envPtr, nil, &si, &pi,
	)
	runtime.KeepAlive(injectedBlock)
	// Close the write end in the parent so reads will get EOF when the child exits.
	_ = windows.CloseHandle(stderrWrite)
	if err != nil {
		_ = windows.CloseHandle(stderrRead)
		return 0, fmt.Errorf("CreateProcessAsUser: %w", err)
	}

	if jobHandle != 0 {
		r, _, e := procAssignProcessToJobObject.Call(uintptr(jobHandle), uintptr(pi.Process))
		if r == 0 {
			log.Warnf("assign agent to job object: %v (orphan possible on service crash)", e)
		}
	}

	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		log.Warnf("resume agent main thread: %v", err)
	}
	_ = windows.CloseHandle(pi.Thread)

	// Relog agent output in the service with a [vnc-agent] prefix.
	go relogAgentOutput(stderrRead)

	log.Infof("spawned agent PID=%d in session %d on %s", pi.ProcessId, sessionID, socketPath)
	return pi.Process, nil
}

// sessionManager monitors the active console session and ensures a VNC agent
// process is running in it. When the session changes (e.g., user switch, RDP
// connect/disconnect), it kills the old agent and spawns a new one. Each
// spawn picks a per-session Unix-socket path the agent binds and the
// daemon dials over local IPC.
type sessionManager struct {
	mu             sync.Mutex
	agentProc      windows.Handle
	everSpawned    bool
	agentStartedAt time.Time
	spawnFailures  int
	nextSpawnAt    time.Time
	sessionID      uint32
	authToken      string
	socketPath     string
	done           chan struct{}
	// jobHandle owns the agent processes via a Windows Job Object with
	// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. When the service exits or crashes,
	// the OS closes the handle and terminates every assigned agent: no
	// orphaned agent processes holding a socket across restarts.
	jobHandle windows.Handle
}

// agentSocketPathFmt parameterizes the per-session agent socket path by
// the Windows session id. C:\Windows\Temp is writable to both the daemon
// (SYSTEM) and the spawned agent (SYSTEM token impersonating the session).
const agentSocketPathFmt = `C:\Windows\Temp\netbird-vnc-%d.sock`

func newSessionManager() *sessionManager {
	m := &sessionManager{sessionID: ^uint32(0), done: make(chan struct{})}
	if h, err := createKillOnCloseJob(); err != nil {
		log.Warnf("create job object for vnc-agent (orphan agents possible after crash): %v", err)
	} else {
		m.jobHandle = h
	}
	return m
}

// createKillOnCloseJob returns a Job Object configured so that closing its
// handle (process exit or explicit Close) terminates every process assigned
// to it. Used to keep orphaned vnc-agent processes from outliving the service.
func createKillOnCloseJob() (windows.Handle, error) {
	r, _, e := procCreateJobObjectW.Call(0, 0)
	if r == 0 {
		return 0, fmt.Errorf("CreateJobObject: %w", e)
	}
	job := windows.Handle(r)

	// JOBOBJECT_EXTENDED_LIMIT_INFORMATION on amd64 = 144 bytes.
	//
	//  JOBOBJECT_BASIC_LIMIT_INFORMATION  (64 bytes with alignment padding)
	//    PerProcessUserTimeLimit  LARGE_INTEGER  off  0
	//    PerJobUserTimeLimit      LARGE_INTEGER  off  8
	//    LimitFlags               DWORD          off 16
	//    [4 byte pad to align SIZE_T]
	//    MinimumWorkingSetSize    SIZE_T         off 24
	//    MaximumWorkingSetSize    SIZE_T         off 32
	//    ActiveProcessLimit       DWORD          off 40
	//    [4 byte pad to align ULONG_PTR]
	//    Affinity                 ULONG_PTR      off 48
	//    PriorityClass            DWORD          off 56
	//    SchedulingClass          DWORD          off 60
	//  IO_COUNTERS (48)  +  4 * SIZE_T (32)  =  144 total.
	//
	// We only set LimitFlags; the rest stays zero.
	const sizeofExtended = 144
	const offsetLimitFlags = 16
	const jobObjectExtendedLimitInformation = 9
	const jobObjectLimitKillOnJobClose = 0x00002000

	var info [sizeofExtended]byte
	binary.LittleEndian.PutUint32(info[offsetLimitFlags:offsetLimitFlags+4], jobObjectLimitKillOnJobClose)

	r, _, e = procSetInformationJobObject.Call(
		uintptr(job),
		uintptr(jobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&info[0])),
		uintptr(sizeofExtended),
	)
	if r == 0 {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject(KILL_ON_JOB_CLOSE): %w", e)
	}
	return job, nil
}

// Resolve returns the current agent socket path and token. When no
// agent is spawned yet (initial boot, between session switches, or
// permanently disabled when SE_TCB_NAME is missing) it surfaces a
// distinct error so the daemon can reject the connection with a
// meaningful message instead of timing out the proxy dial.
func (m *sessionManager) Resolve(_ context.Context) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.socketPath == "" {
		return "", "", errAgentNotReady
	}
	return m.socketPath, m.authToken, nil
}

var errAgentNotReady = errors.New("VNC agent not running yet")

// Stop signals the session manager to exit its polling loop and closes the
// Job Object handle, which Windows uses as the trigger to terminate every
// agent process this manager spawned.
func (m *sessionManager) Stop() {
	select {
	case <-m.done:
	default:
		close(m.done)
	}
	m.mu.Lock()
	if m.jobHandle != 0 {
		_ = windows.CloseHandle(m.jobHandle)
		m.jobHandle = 0
	}
	m.mu.Unlock()
}

func (m *sessionManager) run() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		if !m.tick() {
			return
		}
		select {
		case <-m.done:
			m.mu.Lock()
			m.killAgent()
			m.mu.Unlock()
			return
		case <-ticker.C:
		}
	}
}

// tick performs one session/agent-state update. Returns false if the manager
// should permanently stop (e.g. missing SYSTEM privileges).
func (m *sessionManager) tick() bool {
	sid := getActiveSessionID()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.handleSessionChange(sid)
	m.reapExitedAgent()
	return m.maybeSpawnAgent(sid)
}

func (m *sessionManager) handleSessionChange(sid uint32) {
	if sid == m.sessionID {
		return
	}
	log.Infof("active session changed: %d -> %d", m.sessionID, sid)
	m.killAgent()
	m.sessionID = sid
}

func (m *sessionManager) reapExitedAgent() {
	if m.agentProc == 0 {
		return
	}
	var code uint32
	if err := windows.GetExitCodeProcess(m.agentProc, &code); err != nil {
		log.Debugf("GetExitCodeProcess: %v", err)
		return
	}
	if code == stillActive {
		return
	}
	m.scheduleNextSpawn(code, time.Since(m.agentStartedAt))
	if err := windows.CloseHandle(m.agentProc); err != nil {
		log.Debugf("close agent handle: %v", err)
	}
	m.agentProc = 0
}

// scheduleNextSpawn applies an exponential backoff on fast crashes (<5s) and
// resets immediately otherwise.
func (m *sessionManager) scheduleNextSpawn(exitCode uint32, lifetime time.Duration) {
	if lifetime < 5*time.Second {
		m.spawnFailures++
		backoff := time.Duration(1<<min(m.spawnFailures, 5)) * time.Second
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		m.nextSpawnAt = time.Now().Add(backoff)
		log.Warnf("agent exited (code=%d) after %v, retrying in %v (failures=%d)", exitCode, lifetime.Round(time.Millisecond), backoff, m.spawnFailures)
		return
	}
	m.spawnFailures = 0
	m.nextSpawnAt = time.Time{}
	log.Infof("agent exited (code=%d) after %v, respawning", exitCode, lifetime.Round(time.Second))
}

// maybeSpawnAgent spawns a new agent if there's no current one and the backoff
// window has elapsed. Returns false to permanently stop the manager when the
// service lacks the privileges needed to spawn cross-session.
func (m *sessionManager) maybeSpawnAgent(sid uint32) bool {
	if m.agentProc != 0 || sid == 0xFFFFFFFF || !time.Now().After(m.nextSpawnAt) {
		return true
	}
	// Reap any orphan still holding the agent port from a previous
	// service instance, only on our very first spawn. Once we own
	// an agent, we manage its lifecycle ourselves and never need to
	// kill an unknown listener; if a kill+respawn races on port
	// release, the spawn-failure backoff handles it without forcing
	// a synchronous wait or duplicate kill.
	socketPath := fmt.Sprintf(agentSocketPathFmt, sid)
	// Covers a previous-run crash that escaped Job Object kill-on-close.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		log.Debugf("clear stale agent socket %s: %v", socketPath, err)
	}
	token, err := generateAuthToken()
	if err != nil {
		log.Warnf("generate agent auth token: %v", err)
		return true
	}
	m.authToken = token
	m.socketPath = socketPath
	h, err := spawnAgentInSession(sid, socketPath, m.authToken, m.jobHandle)
	if err != nil {
		m.authToken = ""
		m.socketPath = ""
		if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			// SE_TCB_NAME (token-impersonation across sessions) is only
			// granted to SYSTEM. Without it spawnAgent will fail every 2
			// seconds forever: log once and give up.
			log.Warnf("VNC service mode disabled: agent spawn requires SYSTEM privileges (got: %v)", err)
			return false
		}
		log.Warnf("spawn agent in session %d: %v", sid, err)
		return true
	}
	m.agentProc = h
	m.agentStartedAt = time.Now()
	m.everSpawned = true
	return true
}

func (m *sessionManager) killAgent() {
	if m.agentProc == 0 {
		return
	}
	_ = windows.TerminateProcess(m.agentProc, 0)
	_ = windows.CloseHandle(m.agentProc)
	m.agentProc = 0
	log.Info("killed old agent")
}

// relogAgentOutput reads log lines from the agent's stderr pipe and
// relogs them with the service's formatter. The *os.File owns the
// underlying handle, so closing it suffices.
func relogAgentOutput(pipe windows.Handle) {
	f := os.NewFile(uintptr(pipe), "vnc-agent-stderr")
	defer func() { _ = f.Close() }()
	relogAgentStream(f)
}

// logCleanupCall invokes a Windows syscall used solely as a cleanup primitive
// (CloseClipboard, ReleaseDC, etc.) and logs failures at trace level. The
// indirection lets us satisfy errcheck without scattering ignored returns at
// each call site, while still capturing diagnostic info when the OS reports
// a failure.
func logCleanupCall(name string, proc *windows.LazyProc) {
	r, _, err := proc.Call()
	if r == 0 && err != nil && err != windows.NTE_OP_OK {
		log.Tracef("%s: %v", name, err)
	}
}

// logCleanupCallArgs is logCleanupCall with one argument; common pattern for
// release-by-handle syscalls.
func logCleanupCallArgs(name string, proc *windows.LazyProc, args ...uintptr) {
	r, _, err := proc.Call(args...)
	if r == 0 && err != nil && err != windows.NTE_OP_OK {
		log.Tracef("%s: %v", name, err)
	}
}
