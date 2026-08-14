//go:build linux

// Command nm-netbird-auth-dialog is the interactive helper NetworkManager
// spawns, inside the user's desktop session, when nm-netbird-service raises
// SecretsRequired for an SSO login. It shows a native GTK4 dialog (hand
// written against libgtk-4 via cgo, not a generated Go binding, since the
// latest gotk4 release fails to compile against this system's GLib) and
// opens the verification URL with xdg-open on confirmation (inheriting the
// session's DISPLAY/DBUS_SESSION_BUS_ADDRESS, unlike the root service).
//
// The acknowledgement is written back to NetworkManager right after Open is
// clicked, not after login actually succeeds: NetworkManager's own
// secrets-request has a hard timeout (observed around 25-40s) far shorter
// than a real human SSO flow can take, so nm-netbird-service is the one
// that waits out the actual login afterward, in a process NM isn't timing.
// This dialog keeps showing progress in the meantime by independently
// watching the daemon's status stream (rather than calling WaitSSOLogin
// itself, which would race nm-netbird-service's own call for the same
// login), closing gracefully once the daemon reports the tunnel is up.
// Cancelling the dialog only stops this dialog's own wait; the connection
// attempt already has its answer by then, so use the normal NetworkManager
// disconnect action to abort it.
package main

/*
#cgo pkg-config: gtk4
#include <stdlib.h>
#include "dialog_linux.h"
*/
import "C"

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/netbirdio/netbird/client/networkmanager/authdialog"
	"github.com/netbirdio/netbird/client/networkmanager/nbdaemon"
	nbproto "github.com/netbirdio/netbird/client/proto"
)

const ssoAckKey = "netbird-sso-acknowledged"

var (
	cancelMu     sync.Mutex
	cancelWaitFn context.CancelFunc
)

func main() {
	// NetworkManager's secret-agent framework closes this process's stderr
	// (and, once it has our answer, stdin) right after spawning it, without
	// ever reading from it. Any later write to that closed pipe -- ours or
	// GTK/Mesa's own startup warnings -- raises SIGPIPE, which by default
	// kills the whole process before it gets a chance to show anything.
	signal.Ignore(syscall.SIGPIPE)

	log.SetOutput(os.Stderr)

	var hints []string
	name := pflag.StringP("name", "n", "", "connection name")
	uuid := pflag.StringP("uuid", "u", "", "connection UUID")
	pflag.StringP("service", "s", "", "VPN service type")
	externalUIMode := pflag.Bool("external-ui-mode", false, "describe the prompt via stdout instead of showing a window")
	pflag.BoolP("allow-interaction", "i", false, "allow showing a UI")
	pflag.Bool("reprompt", false, "force reprompting for secrets")
	pflag.StringArrayVarP(&hints, "hint", "t", nil, "hint about which secret is needed, repeatable")
	pflag.CommandLine.ParseErrorsAllowlist.UnknownFlags = true
	pflag.Parse()

	verificationURI, _ := authdialog.ParseHints(hints)
	if verificationURI == "" {
		if err := authdialog.WriteNoSecretsRequired(os.Stdout); err != nil {
			log.Warnf("write no-secret response: %v", err)
		}
		return
	}

	release, err := acquireSingleInstance(*uuid)
	if err != nil {
		log.Warnf("single-instance lock: %v", err)
	} else {
		defer release()
	}

	ackOnOpen = func() {
		if *externalUIMode {
			if err := authdialog.WriteExternalUI(os.Stdout, "NetBird SSO Login",
				"Open the link in your browser to sign in to NetBird.", ssoAckKey); err != nil {
				log.Warnf("write external UI description: %v", err)
			}
		} else if err := authdialog.WriteSecrets(os.Stdout, map[string]string{ssoAckKey: "yes"}); err != nil {
			log.Warnf("write ack secret: %v", err)
		}

		// The secret-agent reads this helper's stdout until EOF to know the
		// answer is complete. Since this process keeps running past this
		// point (to show "waiting..." and watch for login completion), the
		// write above would otherwise sit unread indefinitely.
		if err := os.Stdout.Close(); err != nil {
			log.Warnf("close stdout: %v", err)
		}
	}

	cName := C.CString(*name)
	defer C.free(unsafe.Pointer(cName))
	cURL := C.CString(verificationURI)
	defer C.free(unsafe.Pointer(cURL))

	C.netbird_dialog_run(cName, cURL)
}

// acquireSingleInstance ensures at most one nm-netbird-auth-dialog runs at a
// time for a given connection UUID. NetworkManager's own secrets-request
// timeout does not cascade a cancel down to an already-spawned auth-dialog
// helper when it gives up waiting, so a helper whose login the user
// abandoned (or that got stuck) can outlive the connection attempt that
// spawned it; retrying the same connection then spawns a second, unrelated
// helper alongside the still-running one, which has been observed to
// confuse the secret agent's per-connection request tracking. Killing any
// stale instance for the same UUID up front, rather than relying on a
// timeout, closes that race regardless of how quickly the user retries.
func acquireSingleInstance(uuid string) (release func(), err error) {
	noop := func() {}
	if uuid == "" {
		return noop, nil
	}

	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "nm-netbird-auth-dialog")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return noop, fmt.Errorf("create lock dir: %w", err)
	}
	path := filepath.Join(dir, uuid+".pid")

	if data, readErr := os.ReadFile(path); readErr == nil {
		if pid, convErr := strconv.Atoi(strings.TrimSpace(string(data))); convErr == nil && pid != os.Getpid() {
			if proc, findErr := os.FindProcess(pid); findErr == nil && proc.Signal(syscall.Signal(0)) == nil {
				log.Warnf("killing stale auth-dialog (pid %d) for the same connection", pid)
				_ = proc.Kill()
			}
		}
	}

	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		return noop, fmt.Errorf("write lock file: %w", err)
	}

	return func() { _ = os.Remove(path) }, nil
}

// ackOnOpen writes NetworkManager's acknowledgement; set in main once flags
// are parsed, since //export functions can't take extra arguments.
var ackOnOpen func()

//export goOpenClicked
func goOpenClicked(curl *C.char) {
	url := C.GoString(curl)
	if err := exec.Command("xdg-open", url).Start(); err != nil {
		log.Warnf("xdg-open %s: %v", url, err)
	}

	ackOnOpen()

	ctx, cancel := context.WithCancel(context.Background())
	cancelMu.Lock()
	cancelWaitFn = cancel
	cancelMu.Unlock()

	go func() {
		err := watchUntilLoggedIn(ctx)
		if err != nil {
			log.Warnf("watch login status: %v", err)
		}

		success := C.int(0)
		if err == nil {
			success = 1
		}
		C.netbird_dialog_finish(success)
	}()
}

//export goCancelled
func goCancelled() {
	cancelMu.Lock()
	cancel := cancelWaitFn
	cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// watchUntilLoggedIn subscribes to the daemon's status stream and returns
// once login has progressed past NeedsLogin, or reports an error on
// LoginFailed or context cancellation. It does not call WaitSSOLogin
// itself, since nm-netbird-service already does and the daemon may not
// support two concurrent waiters for the same login.
func watchUntilLoggedIn(ctx context.Context) error {
	conn, err := nbdaemon.Dial()
	if err != nil {
		return fmt.Errorf("dial netbird daemon: %w", err)
	}
	defer conn.Close()

	client := nbproto.NewDaemonServiceClient(conn)
	stream, err := client.SubscribeStatus(ctx, &nbproto.StatusRequest{})
	if err != nil {
		return fmt.Errorf("subscribe status: %w", err)
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			return err
		}

		switch resp.Status {
		case "Connecting", "Connected":
			return nil
		case "LoginFailed", "SessionExpired":
			return fmt.Errorf("netbird status: %s", resp.Status)
		}
	}
}
