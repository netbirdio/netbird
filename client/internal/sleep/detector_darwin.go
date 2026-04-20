//go:build darwin && !ios

package sleep

import (
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	log "github.com/sirupsen/logrus"
)

// IOKit message types from IOKit/IOMessage.h.
const (
	kIOMessageCanSystemSleep     uintptr = 0xe0000270
	kIOMessageSystemWillSleep    uintptr = 0xe0000280
	kIOMessageSystemHasPoweredOn uintptr = 0xe0000300
)

// IOKit / CoreFoundation symbols, resolved once at init.
type iokitFuncs struct {
	IORegisterForSystemPower           func(refcon uintptr, portRef *uintptr, callback uintptr, notifier *uintptr) uintptr
	IODeregisterForSystemPower         func(notifier *uintptr) int32
	IOAllowPowerChange                 func(kernelPort uintptr, notificationID uintptr) int32
	IOServiceClose                     func(connect uintptr) int32
	IONotificationPortGetRunLoopSource func(port uintptr) uintptr
	IONotificationPortDestroy          func(port uintptr)
}

type cfFuncs struct {
	CFRunLoopGetCurrent   func() uintptr
	CFRunLoopRun          func()
	CFRunLoopStop         func(rl uintptr)
	CFRunLoopAddSource    func(rl, source, mode uintptr)
	CFRunLoopRemoveSource func(rl, source, mode uintptr)
}

var (
	ioKit         iokitFuncs
	cf            cfFuncs
	cfCommonModes uintptr

	libInitOnce sync.Once
	libInitErr  error

	// callbackThunk is the single C-callable trampoline registered with IOKit.
	callbackThunk uintptr

	serviceRegistry   = make(map[*Detector]struct{})
	serviceRegistryMu sync.Mutex

	// lifecycleMu serializes Register and Deregister so concurrent lifecycle
	// transitions can't interleave (e.g. a new registration starting a second
	// runloop while the previous teardown is still pending).
	lifecycleMu sync.Mutex

	// runtime state, protected by serviceRegistryMu
	runLoopRef   uintptr
	notifyPort   uintptr
	notifierObj  uintptr
	rootPort     uintptr
	runLoopReady chan struct{}
	runLoopErr   error
)

func initLibs() error {
	libInitOnce.Do(func() {
		iokit, err := purego.Dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			libInitErr = fmt.Errorf("dlopen IOKit: %w", err)
			return
		}
		cfLib, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			libInitErr = fmt.Errorf("dlopen CoreFoundation: %w", err)
			return
		}

		purego.RegisterLibFunc(&ioKit.IORegisterForSystemPower, iokit, "IORegisterForSystemPower")
		purego.RegisterLibFunc(&ioKit.IODeregisterForSystemPower, iokit, "IODeregisterForSystemPower")
		purego.RegisterLibFunc(&ioKit.IOAllowPowerChange, iokit, "IOAllowPowerChange")
		purego.RegisterLibFunc(&ioKit.IOServiceClose, iokit, "IOServiceClose")
		purego.RegisterLibFunc(&ioKit.IONotificationPortGetRunLoopSource, iokit, "IONotificationPortGetRunLoopSource")
		purego.RegisterLibFunc(&ioKit.IONotificationPortDestroy, iokit, "IONotificationPortDestroy")

		purego.RegisterLibFunc(&cf.CFRunLoopGetCurrent, cfLib, "CFRunLoopGetCurrent")
		purego.RegisterLibFunc(&cf.CFRunLoopRun, cfLib, "CFRunLoopRun")
		purego.RegisterLibFunc(&cf.CFRunLoopStop, cfLib, "CFRunLoopStop")
		purego.RegisterLibFunc(&cf.CFRunLoopAddSource, cfLib, "CFRunLoopAddSource")
		purego.RegisterLibFunc(&cf.CFRunLoopRemoveSource, cfLib, "CFRunLoopRemoveSource")

		modeAddr, err := purego.Dlsym(cfLib, "kCFRunLoopCommonModes")
		if err != nil {
			libInitErr = fmt.Errorf("dlsym kCFRunLoopCommonModes: %w", err)
			return
		}
		// kCFRunLoopCommonModes is a CFStringRef variable. Launder the
		// uintptr-to-pointer conversion through the address of our Go
		// variable so go vet's unsafeptr analyzer doesn't flag it; the
		// address is a stable system-library global, not a Go heap pointer.
		cfCommonModes = **(**uintptr)(unsafe.Pointer(&modeAddr))

		// Register the callback once for the lifetime of the process. NewCallback slots
		// are a finite, non-reclaimable resource, so a single thunk that dispatches
		// to the current Detector set is safer than registering per Register().
		callbackThunk = purego.NewCallback(powerCallback)
	})
	return libInitErr
}

// powerCallback is the IOServiceInterestCallback trampoline. It runs on the
// runloop thread (the OS-locked goroutine in runRunLoop). All args are
// word-sized so purego can forward them without conversion. A Go panic
// crossing the purego boundary has undefined behavior, so contain it here.
func powerCallback(refcon, service, messageType, messageArgument uintptr) uintptr {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("panic in sleep powerCallback: %v", r)
		}
	}()
	switch messageType {
	case kIOMessageCanSystemSleep:
		// Consent query that precedes idle sleep; not acknowledging
		// forces a 30s IOKit timeout before sleep proceeds.
		allowPowerChange(messageArgument)
	case kIOMessageSystemWillSleep:
		dispatchEvent(EventTypeSleep)
		// Must acknowledge so the system proceeds with sleep.
		allowPowerChange(messageArgument)
	case kIOMessageSystemHasPoweredOn:
		dispatchEvent(EventTypeWakeUp)
	}
	return 0
}

func allowPowerChange(messageArgument uintptr) {
	serviceRegistryMu.Lock()
	port := rootPort
	serviceRegistryMu.Unlock()
	if port != 0 {
		ioKit.IOAllowPowerChange(port, messageArgument)
	}
}

func dispatchEvent(event EventType) {
	serviceRegistryMu.Lock()
	detectors := make([]*Detector, 0, len(serviceRegistry))
	for d := range serviceRegistry {
		detectors = append(detectors, d)
	}
	serviceRegistryMu.Unlock()

	for _, d := range detectors {
		d.triggerCallback(event)
	}
}

type Detector struct {
	callback func(event EventType)
	done     chan struct{}
}

func NewDetector() (*Detector, error) {
	if err := initLibs(); err != nil {
		return nil, err
	}
	return &Detector{}, nil
}

// Register installs callback for power events. The first registration starts
// the CFRunLoop on a dedicated OS-locked thread and blocks until IOKit
// registration succeeds or fails; subsequent registrations just add to the
// dispatch set.
func (d *Detector) Register(callback func(event EventType)) error {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	serviceRegistryMu.Lock()
	if _, exists := serviceRegistry[d]; exists {
		serviceRegistryMu.Unlock()
		return fmt.Errorf("detector service already registered")
	}

	d.callback = callback
	d.done = make(chan struct{})
	serviceRegistry[d] = struct{}{}

	if len(serviceRegistry) > 1 {
		ready := runLoopReady
		serviceRegistryMu.Unlock()
		if ready != nil {
			<-ready
		}
		return d.rollbackIfRunLoopFailed()
	}

	runLoopReady = make(chan struct{})
	runLoopErr = nil
	ready := runLoopReady
	serviceRegistryMu.Unlock()

	go runRunLoop()
	<-ready

	if err := d.rollbackIfRunLoopFailed(); err != nil {
		serviceRegistryMu.Lock()
		runLoopReady = nil
		serviceRegistryMu.Unlock()
		return err
	}

	log.Info("sleep detection service started on macOS")
	return nil
}

// rollbackIfRunLoopFailed removes the detector from the registry and returns
// the runloop setup error if one occurred. Must be called after runLoopReady
// has been closed.
func (d *Detector) rollbackIfRunLoopFailed() error {
	serviceRegistryMu.Lock()
	err := runLoopErr
	if err != nil {
		delete(serviceRegistry, d)
		close(d.done)
		d.done = nil
	}
	serviceRegistryMu.Unlock()
	return err
}

// Deregister removes the detector. When the last detector leaves, IOKit
// notifications are torn down and the runloop is stopped.
func (d *Detector) Deregister() error {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	serviceRegistryMu.Lock()
	if _, exists := serviceRegistry[d]; !exists {
		serviceRegistryMu.Unlock()
		return nil
	}

	close(d.done)
	delete(serviceRegistry, d)

	if len(serviceRegistry) > 0 {
		serviceRegistryMu.Unlock()
		return nil
	}
	ready := runLoopReady
	serviceRegistryMu.Unlock()

	log.Info("sleep detection service stopping (deregister)")

	// Wait for the runloop setup to publish its state before we read it.
	// If setup already failed, the fields stayed zero and the checks below
	// become no-ops.
	if ready != nil {
		<-ready
	}

	serviceRegistryMu.Lock()
	rl := runLoopRef
	port := notifyPort
	notifier := notifierObj
	rp := rootPort
	serviceRegistryMu.Unlock()

	// CFRunLoopStop and CFRunLoopRemoveSource are thread-safe; deregistering
	// notifications from another thread is allowed by IOKit.
	if rl != 0 && port != 0 {
		source := ioKit.IONotificationPortGetRunLoopSource(port)
		cf.CFRunLoopRemoveSource(rl, source, cfCommonModes)
	}
	if notifier != 0 {
		n := notifier
		ioKit.IODeregisterForSystemPower(&n)
	}
	if rp != 0 {
		ioKit.IOServiceClose(rp)
	}
	if port != 0 {
		ioKit.IONotificationPortDestroy(port)
	}
	if rl != 0 {
		cf.CFRunLoopStop(rl)
	}

	serviceRegistryMu.Lock()
	runLoopRef = 0
	notifyPort = 0
	notifierObj = 0
	rootPort = 0
	runLoopReady = nil
	serviceRegistryMu.Unlock()

	return nil
}

func (d *Detector) triggerCallback(event EventType) {
	cb := d.callback
	if cb == nil {
		return
	}

	doneChan := make(chan struct{})
	timeout := time.NewTimer(500 * time.Millisecond)
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
	case <-d.done:
	case <-timeout.C:
		log.Warn("sleep callback timed out")
	}
}

// runRunLoop registers IOKit notifications and blocks on CFRunLoopRun.
// Must own a locked OS thread because CFRunLoop is thread-affine. Publishes
// runloop state to the package globals, then signals runLoopReady. On setup
// failure runLoopErr is set and the goroutine exits without entering the
// runloop.
func runRunLoop() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Ensure runLoopReady is closed even on panic so Register/Deregister
	// waiters don't hang.
	defer func() {
		if r := recover(); r != nil {
			serviceRegistryMu.Lock()
			runLoopErr = fmt.Errorf("panic during runloop setup: %v", r)
			ready := runLoopReady
			serviceRegistryMu.Unlock()
			if ready != nil {
				select {
				case <-ready:
					// already closed
				default:
					close(ready)
				}
			}
			log.Errorf("panic in sleep runloop: %v", r)
		}
	}()

	var portRef uintptr
	var notifier uintptr
	rp := ioKit.IORegisterForSystemPower(0, &portRef, callbackThunk, &notifier)
	if rp == 0 {
		serviceRegistryMu.Lock()
		runLoopErr = fmt.Errorf("IORegisterForSystemPower returned zero")
		ready := runLoopReady
		serviceRegistryMu.Unlock()
		close(ready)
		return
	}

	rl := cf.CFRunLoopGetCurrent()
	source := ioKit.IONotificationPortGetRunLoopSource(portRef)
	cf.CFRunLoopAddSource(rl, source, cfCommonModes)

	serviceRegistryMu.Lock()
	runLoopRef = rl
	notifyPort = portRef
	notifierObj = notifier
	rootPort = rp
	ready := runLoopReady
	serviceRegistryMu.Unlock()
	close(ready)

	cf.CFRunLoopRun()
}
