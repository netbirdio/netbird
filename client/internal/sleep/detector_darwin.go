//go:build darwin && !ios

package sleep

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>
#include <CoreFoundation/CoreFoundation.h>

extern void sleepCallbackBridge();

// C global variables for IOKit state
static IONotificationPortRef g_notifyPortRef = NULL;
static io_object_t g_notifierObject = 0;
static io_connect_t g_rootPort = 0;
static CFRunLoopRef g_runLoop = NULL;

static void sleepCallback(void* refCon, io_service_t service, natural_t messageType, void* messageArgument) {
	switch (messageType) {
		case kIOMessageSystemWillSleep:
			sleepCallbackBridge();
			IOAllowPowerChange(g_rootPort, (long)messageArgument);
			break;
		default:
			break;
	}
}

static void registerNotifications() {
	g_rootPort = IORegisterForSystemPower(
		NULL,
		&g_notifyPortRef,
		(IOServiceInterestCallback)sleepCallback,
		&g_notifierObject
	);

	if (g_rootPort == 0) {
		return;
	}

	CFRunLoopAddSource(CFRunLoopGetCurrent(),
		IONotificationPortGetRunLoopSource(g_notifyPortRef),
		kCFRunLoopCommonModes);

	g_runLoop = CFRunLoopGetCurrent();
	CFRunLoopRun();
}

static void unregisterNotifications() {
	CFRunLoopRemoveSource(g_runLoop,
		IONotificationPortGetRunLoopSource(g_notifyPortRef),
		kCFRunLoopCommonModes);

	IODeregisterForSystemPower(&g_notifierObject);
	IOServiceClose(g_rootPort);
	IONotificationPortDestroy(g_notifyPortRef);
	CFRunLoopStop(g_runLoop);

	g_notifyPortRef = NULL;
	g_notifierObject = 0;
	g_rootPort = 0;
	g_runLoop = NULL;
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
)

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

	// CFRunLoop must run on a single fixed OS thread
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		C.registerNotifications()
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

	// Deregister IOKit notifications, stop runloop, and free resources
	C.unregisterNotifications()

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
