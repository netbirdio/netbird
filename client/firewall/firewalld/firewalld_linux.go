//go:build linux

package firewalld

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"
)

const (
	dbusDest      = "org.fedoraproject.FirewallD1"
	dbusPath      = "/org/fedoraproject/FirewallD1"
	dbusRootIface = "org.fedoraproject.FirewallD1"
	dbusZoneIface = "org.fedoraproject.FirewallD1.zone"

	errZoneAlreadySet = "ZONE_ALREADY_SET"
	errAlreadyEnabled = "ALREADY_ENABLED"
	errUnknownIface   = "UNKNOWN_INTERFACE"
	errNotEnabled     = "NOT_ENABLED"

	// callTimeout bounds each individual DBus or firewall-cmd invocation.
	// A fresh context is created for each call so a slow DBus probe can't
	// exhaust the deadline before the firewall-cmd fallback gets to run.
	callTimeout = 3 * time.Second
)

var (
	errDBusUnavailable = errors.New("firewalld dbus unavailable")

	// trustLogOnce ensures the "added to trusted zone" message is logged at
	// Info level only for the first successful add per process; repeat adds
	// from other init paths are quieter.
	trustLogOnce sync.Once

	parentCtxMu sync.RWMutex
	parentCtx   context.Context = context.Background()
)

// SetParentContext installs a parent context whose cancellation aborts any
// in-flight TrustInterface call. It does not affect UntrustInterface, which
// always uses a fresh Background-rooted timeout so cleanup can still run
// during engine shutdown when the engine context is already cancelled.
func SetParentContext(ctx context.Context) {
	parentCtxMu.Lock()
	parentCtx = ctx
	parentCtxMu.Unlock()
}

func getParentContext() context.Context {
	parentCtxMu.RLock()
	defer parentCtxMu.RUnlock()
	return parentCtx
}

// TrustInterface places iface into firewalld's trusted zone if firewalld is
// running. It is idempotent and best-effort: errors are returned so callers
// can log, but a non-running firewalld is not an error. Only the first
// successful call per process logs at Info. Respects the parent context set
// via SetParentContext so startup-time cancellation unblocks it.
func TrustInterface(iface string) error {
	parent := getParentContext()
	if !isRunning(parent) {
		return nil
	}
	if err := addTrusted(parent, iface); err != nil {
		return fmt.Errorf("add %s to firewalld trusted zone: %w", iface, err)
	}
	trustLogOnce.Do(func() {
		log.Infof("added %s to firewalld trusted zone", iface)
	})
	log.Debugf("firewalld: ensured %s is in trusted zone", iface)
	return nil
}

// UntrustInterface removes iface from firewalld's trusted zone if firewalld
// is running. Idempotent. Uses a Background-rooted timeout so it still runs
// during shutdown after the engine context has been cancelled.
func UntrustInterface(iface string) error {
	if !isRunning(context.Background()) {
		return nil
	}
	if err := removeTrusted(context.Background(), iface); err != nil {
		return fmt.Errorf("remove %s from firewalld trusted zone: %w", iface, err)
	}
	return nil
}

func newCallContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, callTimeout)
}

func isRunning(parent context.Context) bool {
	ctx, cancel := newCallContext(parent)
	ok, err := isRunningDBus(ctx)
	cancel()
	if err == nil {
		return ok
	}
	if errors.Is(err, errDBusUnavailable) || errors.Is(err, context.DeadlineExceeded) {
		ctx, cancel = newCallContext(parent)
		defer cancel()
		return isRunningCLI(ctx)
	}
	return false
}

func addTrusted(parent context.Context, iface string) error {
	ctx, cancel := newCallContext(parent)
	err := addDBus(ctx, iface)
	cancel()
	if err == nil {
		return nil
	}
	if !errors.Is(err, errDBusUnavailable) {
		log.Debugf("firewalld: dbus add failed, falling back to firewall-cmd: %v", err)
	}
	ctx, cancel = newCallContext(parent)
	defer cancel()
	return addCLI(ctx, iface)
}

func removeTrusted(parent context.Context, iface string) error {
	ctx, cancel := newCallContext(parent)
	err := removeDBus(ctx, iface)
	cancel()
	if err == nil {
		return nil
	}
	if !errors.Is(err, errDBusUnavailable) {
		log.Debugf("firewalld: dbus remove failed, falling back to firewall-cmd: %v", err)
	}
	ctx, cancel = newCallContext(parent)
	defer cancel()
	return removeCLI(ctx, iface)
}

func isRunningDBus(ctx context.Context) (bool, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return false, fmt.Errorf("%w: %v", errDBusUnavailable, err)
	}
	obj := conn.Object(dbusDest, dbusPath)

	var zone string
	if err := obj.CallWithContext(ctx, dbusRootIface+".getDefaultZone", 0).Store(&zone); err != nil {
		return false, fmt.Errorf("firewalld getDefaultZone: %w", err)
	}
	return true, nil
}

func isRunningCLI(ctx context.Context) bool {
	if _, err := exec.LookPath("firewall-cmd"); err != nil {
		return false
	}
	return exec.CommandContext(ctx, "firewall-cmd", "--state").Run() == nil
}

func addDBus(ctx context.Context, iface string) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("%w: %v", errDBusUnavailable, err)
	}
	obj := conn.Object(dbusDest, dbusPath)

	call := obj.CallWithContext(ctx, dbusZoneIface+".addInterface", 0, TrustedZone, iface)
	if call.Err == nil {
		return nil
	}

	if dbusErrContains(call.Err, errAlreadyEnabled) {
		return nil
	}

	if dbusErrContains(call.Err, errZoneAlreadySet) {
		move := obj.CallWithContext(ctx, dbusZoneIface+".changeZoneOfInterface", 0, TrustedZone, iface)
		if move.Err != nil {
			return fmt.Errorf("firewalld changeZoneOfInterface: %w", move.Err)
		}
		return nil
	}

	return fmt.Errorf("firewalld addInterface: %w", call.Err)
}

func removeDBus(ctx context.Context, iface string) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("%w: %v", errDBusUnavailable, err)
	}
	obj := conn.Object(dbusDest, dbusPath)

	call := obj.CallWithContext(ctx, dbusZoneIface+".removeInterface", 0, TrustedZone, iface)
	if call.Err == nil {
		return nil
	}

	if dbusErrContains(call.Err, errUnknownIface) || dbusErrContains(call.Err, errNotEnabled) {
		return nil
	}

	return fmt.Errorf("firewalld removeInterface: %w", call.Err)
}

func addCLI(ctx context.Context, iface string) error {
	if _, err := exec.LookPath("firewall-cmd"); err != nil {
		return fmt.Errorf("firewall-cmd not available: %w", err)
	}

	// --change-interface (no --permanent) binds the interface for the
	// current runtime only; we do not want membership to persist across
	// reboots because netbird re-asserts it on every startup.
	out, err := exec.CommandContext(ctx,
		"firewall-cmd", "--zone="+TrustedZone, "--change-interface="+iface,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("firewall-cmd change-interface: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeCLI(ctx context.Context, iface string) error {
	if _, err := exec.LookPath("firewall-cmd"); err != nil {
		return fmt.Errorf("firewall-cmd not available: %w", err)
	}

	out, err := exec.CommandContext(ctx,
		"firewall-cmd", "--zone="+TrustedZone, "--remove-interface="+iface,
	).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, errUnknownIface) || strings.Contains(msg, errNotEnabled) {
			return nil
		}
		return fmt.Errorf("firewall-cmd remove-interface: %w: %s", err, msg)
	}
	return nil
}

func dbusErrContains(err error, code string) bool {
	if err == nil {
		return false
	}
	var de dbus.Error
	if errors.As(err, &de) {
		for _, b := range de.Body {
			if s, ok := b.(string); ok && strings.Contains(s, code) {
				return true
			}
		}
	}
	return strings.Contains(err.Error(), code)
}
