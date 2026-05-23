//go:build darwin && !ios

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// darwinAgentManager spawns a per-user VNC agent on demand and keeps it
// alive across multiple client connections within the same console-user
// session. A new agent is spawned the first time a client connects, or
// whenever the console user changes underneath us.
//
// Lifecycle is lazy by design: a daemon that never receives a VNC
// connection never spawns anything. The trade-off versus an eager spawn
// (the Windows model) is that the first VNC client pays the launchctl
// asuser + listen-readiness wait, ~hundreds of milliseconds in practice.
// That cost only repeats on user switch.
type darwinAgentManager struct {
	mu         sync.Mutex
	authToken  string
	socketPath string
	uid        uint32
	running    bool
}

func newDarwinAgentManager(ctx context.Context) *darwinAgentManager {
	m := &darwinAgentManager{}
	go m.watchConsoleUser(ctx)
	return m
}

// agentSocketPathFmt parameterizes the agent's loopback Unix-socket path
// by the console uid: /tmp is writable in the launchctl-asuser context
// and predictable to the daemon. The agent chmods the file 0600 after
// bind so only its uid (plus root) can dial.
const agentSocketPathFmt = "/tmp/netbird-vnc-%d.sock"

// watchConsoleUser kills the cached agent whenever the console user
// changes (logout, fast user switch, login window). Without it the daemon
// keeps proxying to an agent whose TCC grant and WindowServer access
// belong to a user who is no longer at the screen, so the new user only
// ever sees the locked-screen wallpaper. Killing the agent breaks the
// loopback TCP that the daemon proxies into, the client disconnects, and
// the next reconnect runs ensure() against the new console uid.
func (m *darwinAgentManager) watchConsoleUser(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			uid, err := consoleUserID()
			m.mu.Lock()
			if !m.running {
				m.mu.Unlock()
				continue
			}
			if err != nil || uid != m.uid {
				prev := m.uid
				m.killLocked()
				m.mu.Unlock()
				if err != nil {
					log.Infof("console user gone (was uid=%d): %v; agent stopped", prev, err)
				} else {
					log.Infof("console user changed %d -> %d; agent stopped, will respawn on next connect", prev, uid)
				}
				continue
			}
			m.mu.Unlock()
		}
	}
}

// Resolve spawns or respawns the per-user agent process as needed and
// returns its Unix-socket path and shared token. Each call is serialized
// so concurrent VNC clients share the same agent.
func (m *darwinAgentManager) Resolve(ctx context.Context) (string, string, error) {
	consoleUID, err := consoleUserID()
	if err != nil {
		return "", "", fmt.Errorf("no console user: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running && m.uid == consoleUID && vncAgentRunning() {
		return m.socketPath, m.authToken, nil
	}
	m.killLocked()
	// Reap stray agents so the new token is the only accepted one.
	killAllVNCAgents()

	socketPath := fmt.Sprintf(agentSocketPathFmt, consoleUID)
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Debugf("clear stale agent socket %s: %v", socketPath, err)
	}

	token, err := generateAuthToken()
	if err != nil {
		return "", "", fmt.Errorf("generate agent auth token: %w", err)
	}
	if err := spawnAgentForUser(consoleUID, socketPath, token); err != nil {
		return "", "", err
	}
	if err := waitForAgent(ctx, socketPath, 5*time.Second); err != nil {
		killAllVNCAgents()
		return "", "", fmt.Errorf("agent did not start listening: %w", err)
	}
	m.authToken = token
	m.socketPath = socketPath
	m.uid = consoleUID
	m.running = true
	log.Infof("spawned VNC agent for console uid=%d on %s", consoleUID, socketPath)
	return socketPath, token, nil
}

// stop terminates the spawned agent, if any. Intended for daemon shutdown.
func (m *darwinAgentManager) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.killLocked()
}

func (m *darwinAgentManager) killLocked() {
	if !m.running {
		return
	}
	killAllVNCAgents()
	if m.socketPath != "" {
		if err := os.Remove(m.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Debugf("remove agent socket %s: %v", m.socketPath, err)
		}
	}
	m.running = false
	m.authToken = ""
	m.socketPath = ""
	m.uid = 0
}

// consoleUserID returns the uid of the user currently sitting at the
// console (the one whose Aqua session is active). Returns
// errNoConsoleUser when nobody is logged in: at the login window
// /dev/console is owned by root.
func consoleUserID() (uint32, error) {
	info, err := os.Stat("/dev/console")
	if err != nil {
		return 0, fmt.Errorf("stat /dev/console: %w", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("/dev/console stat has unexpected type")
	}
	if st.Uid == 0 {
		return 0, errNoConsoleUser
	}
	return st.Uid, nil
}

// spawnAgentForUser uses launchctl asuser to start a netbird vnc-agent
// process inside the target user's launchd bootstrap namespace. That is
// the only spawn mode on macOS that gives the child access to the user's
// WindowServer. The agent's stderr is relogged into the daemon log so
// startup failures are not silently lost when the readiness check times
// out.
func spawnAgentForUser(uid uint32, socketPath, token string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own executable: %w", err)
	}
	cmd := exec.Command(
		"/bin/launchctl", "asuser", strconv.FormatUint(uint64(uid), 10),
		exe, vncAgentSubcommand, "--socket", socketPath,
	)
	cmd.Env = append(os.Environ(), agentTokenEnvVar+"="+token)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("agent stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launchctl asuser: %w", err)
	}
	go func() {
		defer stderr.Close()
		relogAgentStream(stderr)
	}()
	go func() { _ = cmd.Wait() }()
	return nil
}

// waitForAgent dials the agent's Unix socket until it answers. Used to
// gate proxy attempts until the spawned process has finished its Start.
func waitForAgent(ctx context.Context, socketPath string, wait time.Duration) error {
	var d net.Dialer
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		dialCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		c, err := d.DialContext(dialCtx, "unix", socketPath)
		cancel()
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout dialing %s", socketPath)
}

// vncAgentRunning reports whether any vnc-agent process exists on the
// system. There is at most one agent per machine, so any match is "the"
// agent.
func vncAgentRunning() bool {
	pids, err := vncAgentPIDs()
	if err != nil {
		log.Debugf("scan for vnc-agent: %v", err)
		return false
	}
	return len(pids) > 0
}

// killAllVNCAgents sends SIGTERM to every process whose argv contains
// "vnc-agent", waits briefly for them to exit, and escalates to SIGKILL
// for any that remain. We enumerate kern.proc.all rather than
// kern.proc.uid because launchctl asuser preserves the caller's uid
// (root) on the spawned child, so a uid-scoped filter would never match.
func killAllVNCAgents() {
	pids, err := vncAgentPIDs()
	if err != nil {
		log.Debugf("scan for vnc-agent: %v", err)
		return
	}
	for _, pid := range pids {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	if len(pids) == 0 {
		return
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		remaining, _ := vncAgentPIDs()
		if len(remaining) == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	leftover, _ := vncAgentPIDs()
	for _, pid := range leftover {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// vncAgentPIDs returns the pids of vnc-agent subprocesses spawned from
// this binary. Matches exactly on argv[0] == our own executable path
// AND argv[1] == "vnc-agent" so unrelated processes that happen to have
// the same name elsewhere in argv are not targeted. Skips pid 0 and 1
// defensively.
func vncAgentPIDs() ([]int, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, fmt.Errorf("sysctl kern.proc.all: %w", err)
	}
	ownExe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve own executable: %w", err)
	}
	var out []int
	for i := range procs {
		pid := int(procs[i].Proc.P_pid)
		if pid <= 1 {
			continue
		}
		argv, err := procArgv(pid)
		if err != nil || !argvIsVNCAgent(argv, ownExe) {
			continue
		}
		out = append(out, pid)
	}
	return out, nil
}

// procArgv reads the kernel's stored argv for pid via the kern.procargs2
// sysctl. Format: 4-byte argc, then argv[0..argc) each NUL-terminated,
// then envp, then padding. We only need argv so we stop after argc.
func procArgv(pid int) ([]string, error) {
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil, err
	}
	if len(raw) < 4 {
		return nil, fmt.Errorf("procargs2 truncated")
	}
	argc := int(raw[0]) | int(raw[1])<<8 | int(raw[2])<<16 | int(raw[3])<<24
	body := raw[4:]
	// Skip the executable path (NUL-terminated) and any zero padding that
	// follows before argv[0].
	end := bytes.IndexByte(body, 0)
	if end < 0 {
		return nil, fmt.Errorf("procargs2 path unterminated")
	}
	body = body[end+1:]
	for len(body) > 0 && body[0] == 0 {
		body = body[1:]
	}
	args := make([]string, 0, argc)
	for i := 0; i < argc; i++ {
		end := bytes.IndexByte(body, 0)
		if end < 0 {
			break
		}
		args = append(args, string(body[:end]))
		body = body[end+1:]
	}
	return args, nil
}

// argvIsVNCAgent reports whether argv belongs to a vnc-agent subprocess
// spawned from our binary. Requires argv[0] to match ownExe exactly and
// argv[1] to be the vnc-agent subcommand. Matches the spawn shape in
// spawnAgentForUser and rejects anything else.
func argvIsVNCAgent(argv []string, ownExe string) bool {
	if len(argv) < 2 || ownExe == "" {
		return false
	}
	return argv[0] == ownExe && argv[1] == vncAgentSubcommand
}
