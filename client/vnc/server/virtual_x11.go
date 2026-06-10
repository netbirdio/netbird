//go:build (linux && !android) || freebsd

package server

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/configs"
)

// VirtualSession manages a virtual X11 display (Xvfb) with a desktop session
// running as a target user. It implements ScreenCapturer and InputInjector by
// delegating to an X11Capturer/X11InputInjector pointed at the virtual display.
const (
	sessionIdleTimeout = 5 * time.Minute

	defaultSessionWidth  uint16 = 1280
	defaultSessionHeight uint16 = 800

	vncXAuthSubdir  = "vnc-xauth"
	vncXAuthNameFmt = "X%s-%d"
)

type VirtualSession struct {
	mu        sync.Mutex
	display   string
	user      *user.User
	uid       uint32
	gid       uint32
	groups    []uint32
	width     uint16
	height    uint16
	xvfb      *exec.Cmd
	desktop   *exec.Cmd
	poller    *X11Poller
	injector  *X11InputInjector
	log       *log.Entry
	stopped   bool
	clients   int
	idleTimer *time.Timer
	// onIdle fires when the idle timeout elapses or the X server dies.
	onIdle func()
	// cookieHex authenticates X clients against our Xvfb instance.
	cookieHex string
	// authFile backs cookieHex on disk for Xvfb (-auth) and the desktop env.
	authFile string
}

// StartVirtualSession creates and starts a virtual X11 session for the given
// user. Requires root privileges to create sessions as other users. width and
// height request the virtual display geometry; 0 values fall back to the
// defaults.
func StartVirtualSession(username string, width, height uint16, logger *log.Entry) (*VirtualSession, error) {
	if os.Getuid() != 0 {
		return nil, fmt.Errorf("virtual sessions require root privileges")
	}

	if _, err := exec.LookPath("Xvfb"); err != nil {
		if _, err := exec.LookPath("Xorg"); err != nil {
			return nil, fmt.Errorf("neither Xvfb nor Xorg found (install xvfb or xserver-xorg)")
		}
		if !hasDummyDriver() {
			return nil, fmt.Errorf("xvfb not found and xorg dummy driver not installed (install xvfb or xf86-video-dummy)")
		}
	}

	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("lookup user %s: %w", username, err)
	}

	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse uid: %w", err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse gid: %w", err)
	}

	groups, err := supplementaryGroups(u)
	if err != nil {
		logger.Debugf("supplementary groups for %s: %v", username, err)
	}

	if width == 0 {
		width = defaultSessionWidth
	}
	if height == 0 {
		height = defaultSessionHeight
	}

	vs := &VirtualSession{
		user:   u,
		uid:    uint32(uid),
		gid:    uint32(gid),
		groups: groups,
		width:  width,
		height: height,
		log:    logger.WithField("vnc_user", username),
	}

	if err := vs.start(); err != nil {
		return nil, err
	}
	return vs, nil
}

func (vs *VirtualSession) start() error {
	display, err := findFreeDisplay()
	if err != nil {
		return fmt.Errorf("find free display: %w", err)
	}
	vs.display = display

	if err := vs.prepareXAuth(); err != nil {
		return fmt.Errorf("prepare xauth: %w", err)
	}

	if err := vs.startXvfb(); err != nil {
		vs.cleanupXAuth()
		return err
	}

	socketPath := fmt.Sprintf("%s/X%s", x11SocketDir, vs.display[1:])
	if err := waitForPath(socketPath, 5*time.Second); err != nil {
		vs.stopXvfb()
		vs.cleanupXAuth()
		return fmt.Errorf("wait for X11 socket %s: %w", socketPath, err)
	}

	// Restrict the X socket to root and the target user.
	if err := os.Chown(socketPath, int(vs.uid), int(vs.gid)); err != nil {
		vs.log.Debugf("chown X socket: %v", err)
	}
	if err := os.Chmod(socketPath, 0700); err != nil {
		vs.log.Debugf("chmod X socket: %v", err)
	}

	vs.poller = NewX11Poller(vs.display, vs.cookieHex)

	injector, err := NewX11InputInjector(vs.display, vs.cookieHex, vs.authFile)
	if err != nil {
		vs.stopXvfb()
		vs.cleanupXAuth()
		return fmt.Errorf("create X11 injector for %s: %w", vs.display, err)
	}
	vs.injector = injector

	if err := vs.startDesktop(); err != nil {
		vs.injector.Close()
		vs.stopXvfb()
		vs.cleanupXAuth()
		return fmt.Errorf("start desktop: %w", err)
	}

	vs.log.Infof("virtual session started: display=%s user=%s", vs.display, vs.user.Username)
	return nil
}

// ClientConnect increments the client count and cancels any idle timer.
func (vs *VirtualSession) ClientConnect() {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	vs.clients++
	if vs.idleTimer != nil {
		vs.idleTimer.Stop()
		vs.idleTimer = nil
	}
}

// ClientDisconnect decrements the client count. When the last client
// disconnects, starts an idle timer that destroys the session.
func (vs *VirtualSession) ClientDisconnect() {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	vs.clients--
	if vs.clients <= 0 {
		vs.clients = 0
		vs.log.Infof("no VNC clients connected, session will be destroyed in %s", sessionIdleTimeout)
		vs.idleTimer = time.AfterFunc(sessionIdleTimeout, vs.idleExpired)
	}
}

// idleExpired is called by the idle timer. It stops the session and
// notifies the session manager via onIdle so it removes us from the map.
// Bails out early if a client reconnected before the timer callback won
// the race (Stop() doesn't cancel an already-firing AfterFunc, so the
// state check has to happen here under vs.mu).
func (vs *VirtualSession) idleExpired() {
	vs.mu.Lock()
	if vs.stopped || vs.clients > 0 {
		vs.mu.Unlock()
		return
	}
	vs.mu.Unlock()

	vs.log.Info("idle timeout reached, destroying virtual session")
	vs.Stop()
	if vs.onIdle != nil {
		vs.onIdle()
	}
}

// isAlive returns true if the session is running and its X server socket exists.
func (vs *VirtualSession) isAlive() bool {
	vs.mu.Lock()
	stopped := vs.stopped
	display := vs.display
	vs.mu.Unlock()

	if stopped {
		return false
	}
	// Verify the X socket still exists on disk.
	socketPath := fmt.Sprintf("%s/X%s", x11SocketDir, display[1:])
	if _, err := os.Stat(socketPath); err != nil {
		return false
	}
	return true
}

// Capturer returns the screen capturer for this virtual session.
func (vs *VirtualSession) Capturer() ScreenCapturer {
	return vs.poller
}

// Injector returns the input injector for this virtual session.
func (vs *VirtualSession) Injector() InputInjector {
	return vs.injector
}

// Display returns the X11 display string (e.g., ":99").
func (vs *VirtualSession) Display() string {
	return vs.display
}

// Stop terminates the virtual session, killing the desktop and Xvfb.
func (vs *VirtualSession) Stop() {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	if vs.stopped {
		return
	}
	vs.stopped = true

	if vs.injector != nil {
		vs.injector.Close()
	}
	if vs.poller != nil {
		vs.poller.Close()
		vs.poller = nil
	}

	vs.stopDesktop()
	vs.stopXvfb()
	vs.cleanupXAuth()

	vs.log.Info("virtual session stopped")
}

func (vs *VirtualSession) startXvfb() error {
	if _, err := exec.LookPath("Xvfb"); err == nil {
		return vs.startXvfbDirect()
	}
	return vs.startXorgDummy()
}

func (vs *VirtualSession) startXvfbDirect() error {
	geom := fmt.Sprintf("%dx%dx24", vs.width, vs.height)
	vs.xvfb = exec.Command("Xvfb", vs.display,
		"-screen", "0", geom,
		"-nolisten", "tcp",
		"-auth", vs.authFile,
	)
	vs.xvfb.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGTERM}

	if err := vs.xvfb.Start(); err != nil {
		return fmt.Errorf("start Xvfb on %s: %w", vs.display, err)
	}
	vs.log.Infof("Xvfb started on %s (pid=%d)", vs.display, vs.xvfb.Process.Pid)

	go vs.monitorXvfb()

	return nil
}

// startXorgDummy starts Xorg with the dummy video driver as a fallback when
// Xvfb is not installed. Most systems with a desktop have Xorg available.
func (vs *VirtualSession) startXorgDummy() error {
	conf := fmt.Sprintf(`Section "Device"
    Identifier "dummy"
    Driver "dummy"
    VideoRam 256000
EndSection
Section "Screen"
    Identifier "screen"
    Device "dummy"
    DefaultDepth 24
    SubSection "Display"
        Depth 24
        Modes "%dx%d"
    EndSubSection
EndSection
`, vs.width, vs.height)
	f, err := os.CreateTemp("", fmt.Sprintf("nbvnc-dummy-%s-*.conf", vs.display[1:]))
	if err != nil {
		return fmt.Errorf("create Xorg dummy config: %w", err)
	}
	confPath := f.Name()
	if _, err := f.WriteString(conf); err != nil {
		f.Close()
		os.Remove(confPath)
		return fmt.Errorf("write Xorg dummy config: %w", err)
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(confPath)
		return fmt.Errorf("chmod Xorg dummy config: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(confPath)
		return fmt.Errorf("close Xorg dummy config: %w", err)
	}

	vs.xvfb = exec.Command("Xorg", vs.display,
		"-config", confPath,
		"-noreset",
		"-nolisten", "tcp",
		"-auth", vs.authFile,
	)
	vs.xvfb.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGTERM}

	if err := vs.xvfb.Start(); err != nil {
		os.Remove(confPath)
		return fmt.Errorf("start Xorg dummy on %s: %w", vs.display, err)
	}
	vs.log.Infof("Xorg (dummy driver) started on %s (pid=%d)", vs.display, vs.xvfb.Process.Pid)

	go func() {
		vs.monitorXvfb()
		os.Remove(confPath)
	}()

	return nil
}

// monitorXvfb waits for the Xvfb/Xorg process to exit. If it exits
// unexpectedly (not via Stop), the session is marked as dead and the
// onIdle callback fires so the session manager removes it from the map.
// The next GetOrCreate call for this user will create a fresh session.
func (vs *VirtualSession) monitorXvfb() {
	if err := vs.xvfb.Wait(); err != nil {
		vs.log.Debugf("X server exited: %v", err)
	}

	vs.mu.Lock()
	alreadyStopped := vs.stopped
	if !alreadyStopped {
		vs.log.Warn("X server exited unexpectedly, marking session as dead")
		vs.stopped = true
		if vs.idleTimer != nil {
			vs.idleTimer.Stop()
			vs.idleTimer = nil
		}
		if vs.injector != nil {
			vs.injector.Close()
		}
		vs.stopDesktop()
		vs.cleanupXAuth()
	}
	onIdle := vs.onIdle
	vs.mu.Unlock()

	if !alreadyStopped && onIdle != nil {
		onIdle()
	}
}

func (vs *VirtualSession) stopXvfb() {
	if vs.xvfb == nil || vs.xvfb.Process == nil {
		return
	}
	if err := syscall.Kill(-vs.xvfb.Process.Pid, syscall.SIGTERM); err != nil {
		vs.log.Debugf("SIGTERM xvfb group: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := syscall.Kill(-vs.xvfb.Process.Pid, syscall.SIGKILL); err != nil {
		vs.log.Debugf("SIGKILL xvfb group: %v", err)
	}
}

func (vs *VirtualSession) startDesktop() error {
	session := detectDesktopSession()

	// Wrap the desktop command with dbus-launch to provide a session bus.
	// Without this, most desktop environments (XFCE, MATE, etc.) fail immediately.
	var args []string
	if _, err := exec.LookPath("dbus-launch"); err == nil {
		args = append([]string{"dbus-launch", "--exit-with-session"}, session...)
	} else {
		args = session
	}

	vs.desktop = exec.Command(args[0], args[1:]...)
	vs.desktop.Dir = vs.user.HomeDir
	vs.desktop.Env = vs.buildUserEnv()
	vs.desktop.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    vs.uid,
			Gid:    vs.gid,
			Groups: vs.groups,
		},
		Setsid:    true,
		Pdeathsig: syscall.SIGTERM,
	}

	if err := vs.desktop.Start(); err != nil {
		return fmt.Errorf("start desktop session (%v): %w", args, err)
	}
	vs.log.Infof("desktop session started: %v (pid=%d)", args, vs.desktop.Process.Pid)

	go vs.monitorDesktop()

	return nil
}

// monitorDesktop waits for the desktop-session process to exit. When the user
// logs out of GNOME/KDE/XFCE/etc., the session process terminates while Xvfb
// keeps running, leaving a blank root window. Tear the whole virtual session
// down so the next connect starts fresh with a login.
func (vs *VirtualSession) monitorDesktop() {
	if err := vs.desktop.Wait(); err != nil {
		vs.log.Debugf("desktop session exited: %v", err)
	}

	vs.mu.Lock()
	alreadyStopped := vs.stopped
	if !alreadyStopped {
		vs.log.Info("desktop session exited (logout), tearing down virtual session")
		vs.stopped = true
		if vs.idleTimer != nil {
			vs.idleTimer.Stop()
			vs.idleTimer = nil
		}
		if vs.injector != nil {
			vs.injector.Close()
		}
		vs.stopXvfb()
		vs.cleanupXAuth()
	}
	onIdle := vs.onIdle
	vs.mu.Unlock()

	if !alreadyStopped && onIdle != nil {
		onIdle()
	}
}

func (vs *VirtualSession) stopDesktop() {
	if vs.desktop == nil || vs.desktop.Process == nil {
		return
	}
	if err := syscall.Kill(-vs.desktop.Process.Pid, syscall.SIGTERM); err != nil {
		vs.log.Debugf("SIGTERM desktop group: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := syscall.Kill(-vs.desktop.Process.Pid, syscall.SIGKILL); err != nil {
		vs.log.Debugf("SIGKILL desktop group: %v", err)
	}
}

func (vs *VirtualSession) buildUserEnv() []string {
	env := []string{
		envDisplay + "=" + vs.display,
		"HOME=" + vs.user.HomeDir,
		"USER=" + vs.user.Username,
		"LOGNAME=" + vs.user.Username,
		"SHELL=" + getUserShell(vs.user.Uid),
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"XDG_RUNTIME_DIR=/run/user/" + vs.user.Uid,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + vs.user.Uid + "/bus",
	}
	if vs.authFile != "" {
		env = append(env, envXAuthority+"="+vs.authFile)
	}
	return env
}

// prepareXAuth generates a per-session cookie and writes it to an
// Xauthority file owned by the target user.
func (vs *VirtualSession) prepareXAuth() error {
	if configs.RuntimeDir == "" {
		return fmt.Errorf("no runtime directory configured for this platform")
	}
	cookie, hexStr, err := generateXAuthCookie()
	if err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("hostname: %w", err)
	}
	displayNum := strings.TrimPrefix(vs.display, ":")
	authPath := filepath.Join(configs.RuntimeDir, vncXAuthSubdir, fmt.Sprintf(vncXAuthNameFmt, displayNum, vs.uid))
	if err := writeXAuthFile(authPath, hostname, displayNum, cookie, vs.uid, vs.gid); err != nil {
		return err
	}
	vs.cookieHex = hexStr
	vs.authFile = authPath
	return nil
}

// cleanupXAuth removes the Xauthority file written by prepareXAuth.
func (vs *VirtualSession) cleanupXAuth() {
	if vs.authFile == "" {
		return
	}
	if err := os.Remove(vs.authFile); err != nil && !os.IsNotExist(err) {
		vs.log.Debugf("remove xauth: %v", err)
	}
	vs.authFile = ""
	vs.cookieHex = ""
}

// detectDesktopSession discovers available desktop sessions from the standard
// /usr/share/xsessions/*.desktop files (FreeDesktop standard, used by all
// display managers). Falls back to a hardcoded list if no .desktop files found.
func detectDesktopSession() []string {
	// Scan xsessions directories (Linux: /usr/share, FreeBSD: /usr/local/share).
	for _, dir := range []string{"/usr/share/xsessions", "/usr/local/share/xsessions"} {
		if cmd := findXSession(dir); cmd != nil {
			return cmd
		}
	}

	// Fallback: try common session commands directly.
	fallbacks := [][]string{
		{"startplasma-x11"},
		{"gnome-session"},
		{"xfce4-session"},
		{"mate-session"},
		{"cinnamon-session"},
		{"openbox-session"},
		{"xterm"},
	}
	for _, s := range fallbacks {
		if _, err := exec.LookPath(s[0]); err == nil {
			return s
		}
	}
	return []string{"xterm"}
}

// sessionPriority defines preference order for desktop environments.
// Lower number = higher priority. Unknown sessions get 100.
var sessionPriority = map[string]int{
	"plasma":   1, // KDE
	"gnome":    2,
	"xfce":     3,
	"mate":     4,
	"cinnamon": 5,
	"lxqt":     6,
	"lxde":     7,
	"budgie":   8,
	"openbox":  20,
	"fluxbox":  21,
	"i3":       22,
	"xinit":    50, // generic user session
	"lightdm":  50,
	"default":  50,
}

func findXSession(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	candidates := collectSessionCandidates(dir, entries)
	if len(candidates) == 0 {
		return nil
	}
	best := bestSessionCandidate(candidates)
	parts := strings.Fields(best.cmd)
	if _, err := exec.LookPath(parts[0]); err != nil {
		return nil
	}
	return parts
}

type sessionCandidate struct {
	cmd      string
	priority int
}

func collectSessionCandidates(dir string, entries []os.DirEntry) []sessionCandidate {
	var out []sessionCandidate
	for _, e := range entries {
		c, ok := parseSessionEntry(dir, e)
		if ok {
			out = append(out, c)
		}
	}
	return out
}

// parseSessionEntry reads a single .desktop file and extracts its Exec
// command plus the priority hint to be used when picking the best session.
func parseSessionEntry(dir string, e os.DirEntry) (sessionCandidate, bool) {
	if !strings.HasSuffix(e.Name(), ".desktop") {
		return sessionCandidate{}, false
	}
	data, err := os.ReadFile(filepath.Join(dir, e.Name()))
	if err != nil {
		return sessionCandidate{}, false
	}
	execCmd := extractExecLine(data)
	if execCmd == "" || execCmd == "default" {
		return sessionCandidate{}, false
	}
	return sessionCandidate{cmd: execCmd, priority: sessionPriorityFor(e.Name(), execCmd)}, true
}

func extractExecLine(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Exec=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Exec="))
		}
	}
	return ""
}

func sessionPriorityFor(name, execCmd string) int {
	pri := 100
	lower := strings.ToLower(name + " " + execCmd)
	for keyword, p := range sessionPriority {
		if strings.Contains(lower, keyword) && p < pri {
			pri = p
		}
	}
	return pri
}

func bestSessionCandidate(candidates []sessionCandidate) sessionCandidate {
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.priority < best.priority {
			best = c
		}
	}
	return best
}

// findFreeDisplay scans for an unused X11 display number.
func findFreeDisplay() (string, error) {
	for n := 50; n < 200; n++ {
		lockFile := fmt.Sprintf("/tmp/.X%d-lock", n)
		socketFile := fmt.Sprintf("%s/X%d", x11SocketDir, n)
		if _, err := os.Stat(lockFile); err == nil {
			continue
		}
		if _, err := os.Stat(socketFile); err == nil {
			continue
		}
		return fmt.Sprintf(":%d", n), nil
	}
	return "", fmt.Errorf("no free X11 display found (checked :50-:199)")
}

// waitForPath polls until a filesystem path exists or the timeout expires.
func waitForPath(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", path)
}

// getUserShell returns the login shell for the given UID.
func getUserShell(uid string) string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "/bin/sh"
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 7 && fields[2] == uid {
			return fields[6]
		}
	}
	return "/bin/sh"
}

// supplementaryGroups returns the supplementary group IDs for a user.
func supplementaryGroups(u *user.User) ([]uint32, error) {
	gids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	var groups []uint32
	for _, g := range gids {
		id, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			continue
		}
		groups = append(groups, uint32(id))
	}
	return groups, nil
}

// sessionManager tracks active virtual sessions by username.
type sessionManager struct {
	mu       sync.Mutex
	sessions map[string]*VirtualSession
	log      *log.Entry
}

func newSessionManager(logger *log.Entry) *sessionManager {
	sm := &sessionManager{
		sessions: make(map[string]*VirtualSession),
		log:      logger,
	}
	sm.sweepStaleXAuth()
	return sm
}

// sweepStaleXAuth removes Xauthority files left over from a previous daemon
// instance whose X servers are no longer running.
func (sm *sessionManager) sweepStaleXAuth() {
	if configs.RuntimeDir == "" {
		return
	}
	dir := filepath.Join(configs.RuntimeDir, vncXAuthSubdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			sm.log.Debugf("scan stale xauth dir: %v", err)
		}
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if err := os.Remove(p); err != nil {
			sm.log.Debugf("remove stale xauth %s: %v", p, err)
		}
	}
}

// GetOrCreate returns an existing virtual session or creates a new one with
// the requested geometry. If a previous session for this user is alive it is
// reused regardless of the requested geometry; the first caller's size wins
// until the session idles out. If a previous session is stopped or its X
// server died, it is replaced.
func (sm *sessionManager) GetOrCreate(username string, width, height uint16) (vncSession, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if vs, ok := sm.sessions[username]; ok {
		if vs.isAlive() {
			return vs, nil
		}
		sm.log.Infof("replacing dead virtual session for %s", username)
		vs.Stop()
		delete(sm.sessions, username)
	}

	vs, err := StartVirtualSession(username, width, height, sm.log)
	if err != nil {
		return nil, err
	}
	vs.onIdle = func() {
		sm.mu.Lock()
		defer sm.mu.Unlock()
		if cur, ok := sm.sessions[username]; ok && cur == vs {
			delete(sm.sessions, username)
			sm.log.Infof("removed idle virtual session for %s", username)
		}
	}
	sm.sessions[username] = vs
	return vs, nil
}

// hasDummyDriver checks common paths for the Xorg dummy video driver.
func hasDummyDriver() bool {
	paths := []string{
		"/usr/lib/xorg/modules/drivers/dummy_drv.so",                  // Debian/Ubuntu
		"/usr/lib64/xorg/modules/drivers/dummy_drv.so",                // RHEL/Fedora
		"/usr/local/lib/xorg/modules/drivers/dummy_drv.so",            // FreeBSD
		"/usr/lib/x86_64-linux-gnu/xorg/modules/drivers/dummy_drv.so", // Debian multiarch
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// StopAll terminates all active virtual sessions.
func (sm *sessionManager) StopAll() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for username, vs := range sm.sessions {
		vs.Stop()
		delete(sm.sessions, username)
		sm.log.Infof("stopped virtual session for %s", username)
	}
}
