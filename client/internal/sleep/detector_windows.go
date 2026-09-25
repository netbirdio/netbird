//go:build windows

package sleep

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// Power broadcast event types delivered to the notification callback.
// https://learn.microsoft.com/en-us/windows/win32/power/power-management-events
const (
	pbtAPMSuspend         uintptr = 0x0004
	pbtAPMResumeSuspend   uintptr = 0x0007
	pbtAPMResumeAutomatic uintptr = 0x0012
	deviceNotifyCallback  uintptr = 0x00000002
)

var (
	// The callback flavor of these functions is exported by user32.dll, not
	// powrprof.dll (which exports the differently-shaped Power* variants).
	user32 = windows.NewLazySystemDLL("user32.dll")

	// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registersuspendresumenotification
	registerSuspendResumeNotification = user32.NewProc("RegisterSuspendResumeNotification")
	// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unregistersuspendresumenotification
	unregisterSuspendResumeNotification = user32.NewProc("UnregisterSuspendResumeNotification")

	libInitOnce sync.Once
	libInitErr  error

	// callbackThunk is the single C-callable trampoline registered with the OS.
	// windows.NewCallback slots are a finite, non-reclaimable resource, so a
	// single thunk dispatches to the Detector identified by the callback Context.
	callbackThunk uintptr

	// registry maps the Context value handed to the OS callback back to the
	// Detector that registered it, mirroring darwin's serviceRegistry.
	registry   = make(map[int]*Detector)
	registryMu sync.Mutex
	nextHandle int

	// lifecycleMu serializes Register/Deregister so concurrent lifecycle calls
	// can't race on the shared registry or the OS registration handle.
	lifecycleMu sync.Mutex
)

// deviceNotifySubscribeParameters is DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS.
// https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-device_notify_subscribe_parameters
type deviceNotifySubscribeParameters struct {
	Callback uintptr
	Context  uintptr
}

// Detector delivers sleep and wake events to a registered callback.
type Detector struct {
	callback func(event EventType)
	done     chan struct{}

	// handle keys this detector in the package registry and is passed to the OS
	// as the callback Context. Zero means the detector is not registered.
	handle int
	// hPowerNotify is the HPOWERNOTIFY returned by RegisterSuspendResumeNotification.
	hPowerNotify uintptr
	// params is kept alive for the lifetime of the registration so the OS never
	// dereferences freed memory.
	params deviceNotifySubscribeParameters
}

// NewDetector resolves powrprof.dll symbols and returns a Detector.
func NewDetector() (*Detector, error) {
	if err := initLibs(); err != nil {
		return nil, err
	}
	return &Detector{}, nil
}

func initLibs() error {
	libInitOnce.Do(func() {
		if err := registerSuspendResumeNotification.Find(); err != nil {
			libInitErr = fmt.Errorf("resolve RegisterSuspendResumeNotification: %w", err)
			return
		}
		if err := unregisterSuspendResumeNotification.Find(); err != nil {
			libInitErr = fmt.Errorf("resolve UnregisterSuspendResumeNotification: %w", err)
			return
		}
		callbackThunk = windows.NewCallback(powerCallback)
	})
	return libInitErr
}

// Register installs callback for power events and subscribes to suspend/resume
// notifications via powrprof.dll.
func (d *Detector) Register(callback func(event EventType)) error {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	registryMu.Lock()
	if d.handle != 0 {
		registryMu.Unlock()
		return fmt.Errorf("detector service already registered")
	}
	d.callback = callback
	d.done = make(chan struct{})
	nextHandle++
	handle := nextHandle
	d.handle = handle
	registry[handle] = d
	registryMu.Unlock()

	d.params = deviceNotifySubscribeParameters{
		Callback: callbackThunk,
		Context:  uintptr(handle),
	}

	ret, _, callErr := registerSuspendResumeNotification.Call(
		uintptr(unsafe.Pointer(&d.params)),
		deviceNotifyCallback,
	)
	if ret == 0 {
		registryMu.Lock()
		delete(registry, handle)
		close(d.done)
		d.done = nil
		d.handle = 0
		registryMu.Unlock()
		return fmt.Errorf("RegisterSuspendResumeNotification failed: %w", callErr)
	}
	d.hPowerNotify = ret

	log.Info("sleep detection service started on Windows")
	return nil
}

// Deregister unsubscribes from power notifications and removes the detector.
func (d *Detector) Deregister() error {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	registryMu.Lock()
	if d.handle == 0 {
		registryMu.Unlock()
		return nil
	}
	handle := d.handle
	hPowerNotify := d.hPowerNotify
	done := d.done
	registryMu.Unlock()

	log.Info("sleep detection service stopping (deregister)")

	// Unregister the OS subscription first. If it fails, leave handle and
	// hPowerNotify intact so a later call can retry the cleanup.
	if hPowerNotify != 0 {
		ret, _, callErr := unregisterSuspendResumeNotification.Call(hPowerNotify)
		if ret == 0 {
			return fmt.Errorf("UnregisterSuspendResumeNotification failed: %w", callErr)
		}
	}

	registryMu.Lock()
	close(done)
	delete(registry, handle)
	d.handle = 0
	d.hPowerNotify = 0
	registryMu.Unlock()

	return nil
}

func (d *Detector) triggerCallback(event EventType, cb func(event EventType), done <-chan struct{}) {
	if cb == nil || done == nil {
		return
	}

	select {
	case <-done:
		return
	default:
	}

	doneChan := make(chan struct{})
	// The OS invokes this callback synchronously on the suspend path, so run the
	// teardown inline with a bounded budget (mirroring the macOS detector) so
	// Down completes before the machine suspends without blocking indefinitely.
	timeout := time.NewTimer(20 * time.Second)
	defer timeout.Stop()

	go func() {
		defer close(doneChan)
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("panic in sleep callback: %v", r)
			}
		}()
		log.Info("sleep detection event fired")
		cb(event)
	}()

	select {
	case <-doneChan:
	case <-done:
	case <-timeout.C:
		log.Warn("sleep callback timed out")
	}
}

// powerCallback is the DEVICE_NOTIFY_CALLBACK_ROUTINE trampoline, invoked by the
// OS on a system thread. A Go panic crossing the syscall boundary has undefined
// behavior, so contain it here. It must return ERROR_SUCCESS (0).
func powerCallback(context uintptr, msgType uintptr, setting uintptr) uintptr {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("panic in sleep powerCallback: %v", r)
		}
	}()

	var event EventType
	switch msgType {
	case pbtAPMSuspend:
		event = EventTypeSleep
	case pbtAPMResumeAutomatic, pbtAPMResumeSuspend:
		event = EventTypeWakeUp
	default:
		return 0
	}

	dispatchEvent(int(context), event)
	return 0
}

func dispatchEvent(handle int, event EventType) {
	registryMu.Lock()
	d := registry[handle]
	var (
		cb   func(event EventType)
		done <-chan struct{}
	)
	if d != nil {
		cb = d.callback
		done = d.done
	}
	registryMu.Unlock()

	if d == nil {
		return
	}
	d.triggerCallback(event, cb, done)
}
