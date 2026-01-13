//go:build darwin && !ios

package sleep

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>
#include <CoreFoundation/CoreFoundation.h>

extern void sleepCallbackBridge();
extern void poweredOnCallbackBridge();
extern void suspendedCallbackBridge();
extern void resumedCallbackBridge();


// C global variables for IOKit state
static IONotificationPortRef g_notifyPortRef = NULL;
static io_object_t g_notifierObject = 0;
static io_object_t g_generalInterestNotifier = 0;
static io_connect_t g_rootPort = 0;
static CFRunLoopRef g_runLoop = NULL;

static void sleepCallback(void* refCon, io_service_t service, natural_t messageType, void* messageArgument) {
	switch (messageType) {
		case kIOMessageSystemWillSleep:
			sleepCallbackBridge();
			IOAllowPowerChange(g_rootPort, (long)messageArgument);
			break;
        case kIOMessageSystemHasPoweredOn:
          	poweredOnCallbackBridge();
          	break;
        case kIOMessageServiceIsSuspended:
			suspendedCallbackBridge();
			break;
		case kIOMessageServiceIsResumed:
			resumedCallbackBridge();
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
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	serviceRegistry   = make(map[*Detector]struct{})
	serviceRegistryMu sync.Mutex
)

//export sleepCallbackBridge
func sleepCallbackBridge() {
	log.Info("sleepCallbackBridge event triggered")

	serviceRegistryMu.Lock()
	defer serviceRegistryMu.Unlock()

	for svc := range serviceRegistry {
		svc.triggerCallback(EventTypeSleep)
	}
}

//export resumedCallbackBridge
func resumedCallbackBridge() {
	log.Info("resumedCallbackBridge event triggered")
}

//export suspendedCallbackBridge
func suspendedCallbackBridge() {
	log.Info("suspendedCallbackBridge event triggered")
}

//export poweredOnCallbackBridge
func poweredOnCallbackBridge() {
	log.Info("poweredOnCallbackBridge event triggered")
	serviceRegistryMu.Lock()
	defer serviceRegistryMu.Unlock()

	for svc := range serviceRegistry {
		svc.triggerCallback(EventTypeWakeUp)
	}
}

type Detector struct {
	callback func(event EventType)
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewDetector() (*Detector, error) {
	return &Detector{}, nil
}

func (d *Detector) Register(callback func(event EventType)) error {
	serviceRegistryMu.Lock()
	defer serviceRegistryMu.Unlock()

	if _, exists := serviceRegistry[d]; exists {
		return fmt.Errorf("detector service already registered")
	}

	d.callback = callback

	d.ctx, d.cancel = context.WithCancel(context.Background())

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

	log.Info("sleep detection service started on macOS")
	return nil
}

// Deregister removes the detector. When the last detector is removed, IOKit registration is torn down
// and the runloop is stopped and cleaned up.
func (d *Detector) Deregister() error {
	serviceRegistryMu.Lock()
	defer serviceRegistryMu.Unlock()
	_, exists := serviceRegistry[d]
	if !exists {
		return nil
	}

	// cancel and remove this detector
	d.cancel()
	delete(serviceRegistry, d)

	// If other Detectors still exist, leave IOKit running
	if len(serviceRegistry) > 0 {
		return nil
	}

	log.Info("sleep detection service stopping (deregister)")

	// Deregister IOKit notifications, stop runloop, and free resources
	C.unregisterNotifications()

	return nil
}

func (d *Detector) triggerCallback(event EventType) {
	doneChan := make(chan struct{})

	timeout := time.NewTimer(500 * time.Millisecond)
	defer timeout.Stop()

	cb := d.callback
	go func(callback func(event EventType)) {
		log.Info("sleep detection event fired")
		callback(event)
		close(doneChan)
	}(cb)

	select {
	case <-doneChan:
	case <-d.ctx.Done():
	case <-timeout.C:
		log.Warnf("sleep callback timed out")
	}
}
