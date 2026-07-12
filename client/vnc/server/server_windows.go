//go:build windows

package server

import (
	"context"
	"fmt"
	"net"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	sasDLL      = windows.NewLazySystemDLL("sas.dll")
	procSendSAS = sasDLL.NewProc("SendSAS")

	procConvertStringSecurityDescriptorToSecurityDescriptor = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
)

// sasSecurityAttributes builds a SECURITY_ATTRIBUTES that grants
// EVENT_MODIFY_STATE only to the SYSTEM account, preventing unprivileged
// local processes from triggering the Secure Attention Sequence.
func sasSecurityAttributes() (*windows.SecurityAttributes, error) {
	// SDDL: grant full access to SYSTEM (creates/waits) and EVENT_MODIFY_STATE
	// to the interactive user (IU) so the VNC agent in the console session can
	// signal it. Other local users and network users are denied.
	sddl, err := windows.UTF16PtrFromString("D:(A;;GA;;;SY)(A;;0x0002;;;IU)")
	if err != nil {
		return nil, err
	}
	var sd uintptr
	r, _, lerr := procConvertStringSecurityDescriptorToSecurityDescriptor.Call(
		uintptr(unsafe.Pointer(sddl)),
		1, // SDDL_REVISION_1
		uintptr(unsafe.Pointer(&sd)),
		0,
	)
	if r == 0 {
		return nil, lerr
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(sd)),
		InheritHandle:      0,
	}, nil
}

// sasOriginalState tracks the SoftwareSASGeneration value present before we
// changed it, so disableSoftwareSAS can restore the machine to its prior
// state on shutdown instead of leaving the policy enabled.
type sasOriginalState struct {
	had   bool   // true if the value existed before we wrote
	value uint32 // its prior DWORD value, if had == true
	// captured stays true once we have read the genuine pre-enable state
	// for the first time, so a second enableSoftwareSAS call (e.g. after
	// a daemon restart with no intervening disable) cannot overwrite the
	// snapshot with our own forced value.
	captured bool
}

var savedSASState sasOriginalState

// enableSoftwareSAS sets the SoftwareSASGeneration registry key to allow
// services to trigger the Secure Attention Sequence via SendSAS. Without this,
// SendSAS silently does nothing on most Windows editions. The original value
// is snapshotted so disableSoftwareSAS can put the system back as it was.
func enableSoftwareSAS() {
	key, _, err := registry.CreateKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		registry.SET_VALUE|registry.QUERY_VALUE,
	)
	if err != nil {
		log.Warnf("open SoftwareSASGeneration registry key: %v", err)
		return
	}
	defer key.Close()

	if !savedSASState.captured {
		if prev, _, err := key.GetIntegerValue("SoftwareSASGeneration"); err == nil {
			savedSASState = sasOriginalState{had: true, value: uint32(prev), captured: true}
		} else {
			savedSASState = sasOriginalState{had: false, captured: true}
		}
	}

	if err := key.SetDWordValue("SoftwareSASGeneration", 1); err != nil {
		log.Warnf("set SoftwareSASGeneration: %v", err)
		return
	}
	log.Debug("SoftwareSASGeneration registry key set to 1 (services allowed)")
}

// disableSoftwareSAS restores the SoftwareSASGeneration value to its
// pre-enable state. Idempotent; safe to call when enableSoftwareSAS never ran.
func disableSoftwareSAS() {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		registry.SET_VALUE,
	)
	if err != nil {
		log.Debugf("open SoftwareSASGeneration for restore: %v", err)
		return
	}
	defer key.Close()

	if savedSASState.had {
		if err := key.SetDWordValue("SoftwareSASGeneration", savedSASState.value); err != nil {
			log.Warnf("restore SoftwareSASGeneration to %d: %v", savedSASState.value, err)
		}
		return
	}
	if err := key.DeleteValue("SoftwareSASGeneration"); err != nil {
		log.Debugf("delete SoftwareSASGeneration: %v", err)
	}
}

// startSASListener creates a named event with a restricted DACL and waits for
// the VNC input injector to signal it. When signaled, it calls SendSAS(FALSE)
// from Session 0 to trigger the Secure Attention Sequence (Ctrl+Alt+Del).
// Only SYSTEM processes can open the event.
//
// sas.dll / SendSAS is part of the Desktop Experience feature: present on
// client SKUs (Win10/11) and Server SKUs with Desktop Experience installed,
// missing on Server Core. We probe for the symbol at startup; if absent we
// don't register the listener and the agent will silently drop SAS keysyms,
// rather than panicking the entire service every time the user clicks
// Ctrl+Alt+Del.
func startSASListener(ctx context.Context) {
	ev, ok := createSASEvent()
	if !ok {
		return
	}
	log.Info("SAS listener ready (Session 0)")
	go runSASListenerLoop(ctx, ev)
}

// createSASEvent prepares the named event handle on which the SAS listener
// waits for client signals. Returns ok=false (with the failure already
// logged) when the platform doesn't support SAS or the event cannot be
// created; the caller must not spawn the listener goroutine in that case.
func createSASEvent() (windows.Handle, bool) {
	if err := procSendSAS.Find(); err != nil {
		log.Warnf("SAS unavailable on this Windows SKU (sas.dll/SendSAS not present): %v", err)
		return 0, false
	}
	enableSoftwareSAS()
	namePtr, err := windows.UTF16PtrFromString(sasEventName)
	if err != nil {
		log.Warnf("SAS listener UTF16: %v", err)
		return 0, false
	}
	sa, err := sasSecurityAttributes()
	if err != nil {
		log.Warnf("build SAS security descriptor: %v", err)
		return 0, false
	}
	ev, err := windows.CreateEvent(sa, 0, 0, namePtr)
	if err != nil {
		log.Warnf("SAS CreateEvent: %v", err)
		return 0, false
	}
	return ev, true
}

// runSASListenerLoop blocks on ev and invokes SendSAS each time it is
// signalled, until ctx is cancelled. Recovers from panics inside SendSAS so
// a future ABI surprise doesn't tear down the service.
func runSASListenerLoop(ctx context.Context, ev windows.Handle) {
	defer func() { _ = windows.CloseHandle(ev) }()
	defer func() {
		if r := recover(); r != nil {
			log.Warnf("SAS listener recovered from panic: %v", r)
		}
	}()
	const pollMillis = 500
	for {
		if ctx.Err() != nil {
			return
		}
		ret, _ := windows.WaitForSingleObject(ev, pollMillis)
		if ret != windows.WAIT_OBJECT_0 {
			continue
		}
		r, _, sasErr := procSendSAS.Call(0) // FALSE = not from service desktop
		if r == 0 {
			log.Warnf("SendSAS: %v", sasErr)
			continue
		}
		log.Info("SendSAS called from Session 0")
	}
}

// enablePrivilege enables a named privilege on the current process token.
func enablePrivilege(name string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("UTF16 privilege name: %w", err)
	}
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}

func (s *Server) platformSessionManager() virtualSessionManager {
	return nil
}

// platformShutdown restores any machine state mutated by platformInit.
func (s *Server) platformShutdown() {
	disableSoftwareSAS()
}

// platformInit starts the SAS listener and enables privileges needed for
// Session 0 operations (agent spawning, SendSAS).
func (s *Server) platformInit() {
	for _, priv := range []string{"SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege"} {
		if err := enablePrivilege(priv); err != nil {
			log.Debugf("enable %s: %v", priv, err)
		}
	}
	startSASListener(s.ctx)
}

// serviceAcceptLoop runs in Session 0. It validates the source IP and
// hands accepted connections to handleServiceConnection, which runs the
// Noise_IK handshake before proxying to the user-session agent.
func (s *Server) serviceAcceptLoop(ln net.Listener) {
	if ln == nil {
		return
	}

	sm := newSessionManager()
	go sm.run()

	log.Info("service mode, proxying connections to agent over Unix socket")

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				sm.Stop()
				return
			default:
			}
			s.log.Debugf("accept VNC connection: %v", err)
			continue
		}

		if !s.tryAcquireConnSlot() {
			s.log.Warnf("rejecting VNC connection from %s: %d concurrent connections in flight", conn.RemoteAddr(), maxConcurrentVNCConns)
			_ = conn.Close()
			continue
		}
		enableTCPKeepAlive(conn, s.log)
		conn = newMetricsConn(conn, s.sessionRecorder)
		s.trackConn(conn)
		go func(c net.Conn) {
			defer s.releaseConnSlot()
			defer s.untrackConn(c)
			s.handleServiceConnection(c, sm)
		}(conn)
	}
}
