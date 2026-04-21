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

// runLoopSession bundles the handles owned by one CFRunLoop lifetime. A nil
// session means no runloop is active and the next Register must start one.
type runLoopSession struct {
	rl       uintptr
	port     uintptr
	notifier uintptr
	rp       uintptr
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
	session           *runLoopSession

	// lifecycleMu serializes Register/Deregister so a new registration can't
	// start a second runloop while a previous teardown is still pending.
	lifecycleMu sync.Mutex
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

// powerCallback is the IOServiceInterestCallback trampoline, invoked on the
// runloop thread. A Go panic crossing the purego boundary has undefined
// behavior, so contain it here.
func powerCallback(refcon, service, messageType, messageArgument uintptr) uintptr {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("panic in sleep powerCallback: %v", r)
		}
	}()
	switch messageType {
	case kIOMessageCanSystemSleep:
		// Not acknowledging forces a 30s IOKit timeout before idle sleep.
		allowPowerChange(messageArgument)
	case kIOMessageSystemWillSleep:
		dispatchEvent(EventTypeSleep)
		allowPowerChange(messageArgument)
	case kIOMessageSystemHasPoweredOn:
		dispatchEvent(EventTypeWakeUp)
	}
	return 0
}

func allowPowerChange(messageArgument uintptr) {
	serviceRegistryMu.Lock()
	var port uintptr
	if session != nil {
		port = session.rp
	}
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
	needSetup := session == nil
	serviceRegistryMu.Unlock()

	if !needSetup {
		return nil
	}

	errCh := make(chan error, 1)
	go runRunLoop(errCh)
	if err := <-errCh; err != nil {
		serviceRegistryMu.Lock()
		delete(serviceRegistry, d)
		close(d.done)
		d.done = nil
		serviceRegistryMu.Unlock()
		return err
	}

	log.Info("sleep detection service started on macOS")
	return nil
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
	sess := session
	session = nil
	serviceRegistryMu.Unlock()

	log.Info("sleep detection service stopping (deregister)")

	if sess == nil {
		return nil
	}

	// CFRunLoop and IOKit teardown calls are safe from a non-runloop thread.
	if sess.rl != 0 && sess.port != 0 {
		source := ioKit.IONotificationPortGetRunLoopSource(sess.port)
		cf.CFRunLoopRemoveSource(sess.rl, source, cfCommonModes)
	}
	if sess.notifier != 0 {
		n := sess.notifier
		ioKit.IODeregisterForSystemPower(&n)
	}
	if sess.rp != 0 {
		ioKit.IOServiceClose(sess.rp)
	}
	if sess.port != 0 {
		ioKit.IONotificationPortDestroy(sess.port)
	}
	if sess.rl != 0 {
		cf.CFRunLoopStop(sess.rl)
	}

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

// runRunLoop owns the OS-locked thread that CFRunLoop is pinned to. Setup
// result is reported on errCh so Register can surface failures synchronously.
func runRunLoop(errCh chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	sess, err := setupSession()
	if err == nil {
		serviceRegistryMu.Lock()
		session = sess
		serviceRegistryMu.Unlock()
	}
	errCh <- err
	if err != nil {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			log.Errorf("panic in sleep runloop: %v", r)
		}
	}()
	cf.CFRunLoopRun()
}

// setupSession performs the IOKit registration on the current thread.
// Panics are converted to errors so runRunLoop never leaves errCh unsent.
func setupSession() (s *runLoopSession, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during runloop setup: %v", r)
		}
	}()

	var portRef, notifier uintptr
	rp := ioKit.IORegisterForSystemPower(0, &portRef, callbackThunk, &notifier)
	if rp == 0 {
		return nil, fmt.Errorf("IORegisterForSystemPower returned zero")
	}

	rl := cf.CFRunLoopGetCurrent()
	source := ioKit.IONotificationPortGetRunLoopSource(portRef)
	cf.CFRunLoopAddSource(rl, source, cfCommonModes)

	return &runLoopSession{rl: rl, port: portRef, notifier: notifier, rp: rp}, nil
}
