//go:build darwin && !ios

package sleep

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>
#include <CoreFoundation/CoreFoundation.h>

extern void sleepCallbackBridge();
extern io_connect_t getRootPort();

void sleepCallback(void* refCon, io_service_t service, natural_t messageType, void* messageArgument) {
	switch (messageType) {
		case kIOMessageSystemWillSleep:
			sleepCallbackBridge();
			IOAllowPowerChange(getRootPort(), (long)messageArgument);
			break;
		default:
			break;
	}
}
*/
import "C"

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	log "github.com/sirupsen/logrus"
)

var (
	serviceRegistry   = make(map[*Detector]struct{})
	serviceRegistryMu sync.Mutex

	// IOKit globals (guard access with serviceRegistryMu)
	notifyPortRef   C.IONotificationPortRef
	notifierObject  C.io_object_t
	rootPort        C.io_connect_t
	runLoop         C.CFRunLoopRef
	runLoopSource   C.CFRunLoopSourceRef
	runLoopAssigned bool
)

//export getRootPort
func getRootPort() C.io_connect_t {
	// rootPort is set under lock in register(); reads here are OK because IO callback runs
	// on the same OS thread as the run loop; still, we simply return the value.
	return rootPort
}

//export sleepCallbackBridge
func sleepCallbackBridge() {
	log.Info("sleep event triggered")

	serviceRegistryMu.Lock()
	defer serviceRegistryMu.Unlock()

	for svc := range serviceRegistry {
		svc.triggerSleepCallbacks()
	}
}

type Detector struct {
	events chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
}

func NewDetector() (*Detector, error) {
	return &Detector{}, nil
}

func (d *Detector) Register() error {
	serviceRegistryMu.Lock()
	defer serviceRegistryMu.Unlock()

	if _, exists := serviceRegistry[d]; exists {
		return fmt.Errorf("detector service already registered")
	}

	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.events = make(chan struct{}, 1)

	if len(serviceRegistry) > 0 {
		serviceRegistry[d] = struct{}{}
		return nil
	}

	serviceRegistry[d] = struct{}{}

	rootPort = C.IORegisterForSystemPower(
		nil,
		&notifyPortRef,
		(C.IOServiceInterestCallback)(C.sleepCallback),
		&notifierObject,
	)

	if rootPort == 0 {
		// cleanup partial registration
		delete(serviceRegistry, d)
		d.cancel()
		return fmt.Errorf("IORegisterForSystemPower failed")
	}

	runLoopSource = C.IONotificationPortGetRunLoopSource(notifyPortRef)
	runLoopAssigned = false

	// CFRunLoop must run on a single fixed OS thread.
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Get the current thread's runloop and add the source there.
		rl := C.CFRunLoopGetCurrent()

		// Protect globals with the same mutex so unregister() won't race.
		serviceRegistryMu.Lock()
		runLoop = rl
		C.CFRunLoopAddSource(runLoop, runLoopSource, C.kCFRunLoopCommonModes)
		runLoopAssigned = true
		serviceRegistryMu.Unlock()

		// Run the loop; this blocks until CFRunLoopStop is called.
		C.CFRunLoopRun()
		// When CFRunLoopRun returns, clean up will be performed in Deregister path.
	}()

	log.Info("Sleep detection service started on macOS")
	return nil
}

// Deregister removes the detector. When the last detector is removed, IOKit registration is torn down
// and the runloop is stopped and cleaned up.
func (d *Detector) Deregister() error {
	serviceRegistryMu.Lock()
	defer serviceRegistryMu.Unlock()
	_, exists := serviceRegistry[d]
	if !exists {
		return nil // nothing to do
	}

	// cancel and remove this detector
	d.cancel()
	delete(serviceRegistry, d)

	// If other Detectors still exist, leave IOKit running
	if len(serviceRegistry) > 0 {
		return nil
	}

	// Last detector removed: stop runloop and deregister from IOKit.
	log.Info("Sleep detection service stopping (deregister)")

	// At this point we hold the lock; we will perform CFRunLoopRemoveSource / CFRunLoopStop
	// while still holding the lock so the runLoop/runLoopSource won't be modified concurrently.
	if runLoopAssigned {
		// Remove source first
		C.CFRunLoopRemoveSource(runLoop, runLoopSource, C.kCFRunLoopCommonModes)

		// Stop the run loop running on the locked OS thread.
		C.CFRunLoopStop(runLoop)

		// Reset run loop globals
		runLoopAssigned = false
	}

	// Deregister IOKit notifications and free resources.
	C.IODeregisterForSystemPower(&notifierObject)
	C.IOServiceClose(rootPort)
	C.IONotificationPortDestroy(notifyPortRef)

	// Clear IOKit globals to avoid reuse mistakes
	rootPort = 0
	notifyPortRef = nil
	notifierObject = 0
	return nil
}

func (d *Detector) Listen(ctx context.Context) error {
	select {
	case <-d.ctx.Done():
		return d.ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	case <-d.events:
		return nil
	}
}

func (d *Detector) triggerSleepCallbacks() {
	select {
	case d.events <- struct{}{}:
	case <-d.ctx.Done():
	default:
	}
}
