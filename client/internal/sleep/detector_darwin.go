//go:build darwin && !ios

package sleep

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>

extern void sleepCallbackBridge();
extern io_connect_t getRootPort();

void sleepCallback(void* refCon, io_service_t service, natural_t messageType, void* messageArgument) {
	switch (messageType) {
		case kIOMessageSystemWillSleep:
			sleepCallbackBridge();
			IOAllowPowerChange(getRootPort(), (long)messageArgument);
			break;
	}
}
*/
import "C"

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
)

var (
	serviceRegistry   = make(map[*Detector]struct{})
	serviceRegistryMu sync.Mutex

	// Global IOKit registration (shared by all Detector instances)
	notifyPortRef  C.IONotificationPortRef
	notifierObject C.io_object_t
	rootPort       C.io_connect_t
)

//export getRootPort
func getRootPort() C.io_connect_t {
	return rootPort
}

//export sleepCallbackBridge
func sleepCallbackBridge() {
	log.Info("System will sleep")

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
	if err := d.register(); err != nil {
		d.cancel()
		return err
	}

	return nil
}

func (d *Detector) Deregister() error {
	d.unregister()
	return nil
}

// Listen todo: consider to use callback to block until gRPC call has been executed
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
		return
	default:
	}
}

func (d *Detector) register() error {
	d.events = make(chan struct{}, 1)

	if len(serviceRegistry) > 0 {
		serviceRegistry[d] = struct{}{}
		return nil
	}

	serviceRegistry[d] = struct{}{}

	// Register with IOKit only on first Detector instance
	rootPort = C.IORegisterForSystemPower(
		nil,
		&notifyPortRef,
		(C.IOServiceInterestCallback)(C.sleepCallback),
		&notifierObject,
	)

	if rootPort == 0 {
		delete(serviceRegistry, d)
		return fmt.Errorf("IORegisterForSystemPower failed")
	}

	runLoopSource := C.IONotificationPortGetRunLoopSource(notifyPortRef)
	C.CFRunLoopAddSource(C.CFRunLoopGetCurrent(), runLoopSource, C.kCFRunLoopCommonModes)

	log.Info("Sleep detection service started on macOS")

	go func() {
		C.CFRunLoopRun()
	}()

	return nil
}

func (d *Detector) unregister() {
	serviceRegistryMu.Lock()
	defer serviceRegistryMu.Unlock()

	if _, exists := serviceRegistry[d]; !exists {
		return
	}
	d.cancel()
	delete(serviceRegistry, d)

	if len(serviceRegistry) > 0 {
		return
	}

	log.Info("Sleep detection service stopping")

	C.CFRunLoopStop(C.CFRunLoopGetCurrent())
	C.IODeregisterForSystemPower(&notifierObject)
	C.IOServiceClose(rootPort)
	C.IONotificationPortDestroy(notifyPortRef)
}
