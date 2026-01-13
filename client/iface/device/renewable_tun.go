//go:build android

package device

import (
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun"
)

// closeAwareDevice wraps a tun.Device along with a flag
// indicating whether its Close method was called.
//
// It also redirects tun.Device's Events() to a separate goroutine
// and closes it when Close is called.
//
// The WaitGroup and CloseOnce fields are used to ensure that the
// goroutine is awaited and closed only once.
type closeAwareDevice struct {
	isClosed atomic.Bool
	tun.Device
	closeEventCh chan struct{}
	wg           sync.WaitGroup
	closeOnce    sync.Once
}

func newClosableDevice(tunDevice tun.Device) *closeAwareDevice {
	return &closeAwareDevice{
		Device:       tunDevice,
		isClosed:     atomic.Bool{},
		closeEventCh: make(chan struct{}),
	}
}

// redirectEvents redirects the Events() method of the underlying tun.Device
// to the given channel (RenewableTUN's events channel).
func (c *closeAwareDevice) redirectEvents(out chan tun.Event) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			select {
			case ev, ok := <-c.Device.Events():
				if !ok {
					return
				}

				if ev == tun.EventDown {
					continue
				}

				select {
				case out <- ev:
				case <-c.closeEventCh:
					return
				}
			case <-c.closeEventCh:
				return
			}
		}
	}()
}

// Close calls the underlying Device's Close method
// after setting isClosed to true.
func (c *closeAwareDevice) Close() (err error) {
	c.closeOnce.Do(func() {
		c.isClosed.Store(true)
		close(c.closeEventCh)
		err = c.Device.Close()
		c.wg.Wait()
	})

	return err
}

func (c *closeAwareDevice) IsClosed() bool {
	return c.isClosed.Load()
}

type RenewableTUN struct {
	devices []*closeAwareDevice
	mu      sync.Mutex
	cond    *sync.Cond
	events  chan tun.Event
	closed  atomic.Bool
}

func NewRenewableTUN() *RenewableTUN {
	r := &RenewableTUN{
		devices: make([]*closeAwareDevice, 0),
		mu:      sync.Mutex{},
		events:  make(chan tun.Event, 16),
	}
	r.cond = sync.NewCond(&r.mu)
	return r
}

func (r *RenewableTUN) File() *os.File {
	for {
		dev := r.peekLast()
		if dev == nil {
			if !r.waitForDevice() {
				return nil
			}
			continue
		}

		file := dev.File()

		if dev.IsClosed() {
			time.Sleep(1 * time.Millisecond)
			continue
		}

		return file
	}
}

// Read reads from an underlying tun.Device kept in the r.devices slice.
// If no device is available, it waits for one to be added via AddDevice().
//
// On error, it retries reading from the newest device instead of returning the error
// if the device is closed; if not, it propagates the error.
func (r *RenewableTUN) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	for {
		dev := r.peekLast()
		if dev == nil {
			// wait until AddDevice() signals a new device via cond.Broadcast()
			if !r.waitForDevice() { // returns false if the renewable TUN itself is closed
				return 0, io.EOF
			}
			continue
		}

		n, err = dev.Read(bufs, sizes, offset)
		if err == nil {
			return n, nil
		}

		// swap in progress; retry on the newest instead of returning the error
		if dev.IsClosed() {
			time.Sleep(1 * time.Millisecond)
			continue
		}
		return n, err // propagate non-swap error
	}
}

// Write writes to underlying tun.Device kept in the r.devices slice.
// If no device is available, it waits for one to be added via AddDevice().
//
// On error, it retries writing to the newest device instead of returning the error
// if the device is closed; if not, it propagates the error.
func (r *RenewableTUN) Write(bufs [][]byte, offset int) (int, error) {
	for {
		dev := r.peekLast()
		if dev == nil {
			if !r.waitForDevice() {
				return 0, io.EOF
			}
			continue
		}

		n, err := dev.Write(bufs, offset)
		if err == nil {
			return n, nil
		}

		if dev.IsClosed() {
			time.Sleep(1 * time.Millisecond)
			continue
		}

		return n, err
	}
}

func (r *RenewableTUN) MTU() (int, error) {
	for {
		dev := r.peekLast()
		if dev == nil {
			if !r.waitForDevice() {
				return 0, io.EOF
			}
			continue
		}
		mtu, err := dev.MTU()
		if err == nil {
			return mtu, nil
		}
		if dev.IsClosed() {
			time.Sleep(1 * time.Millisecond)
			continue
		}
		return 0, err
	}
}

func (r *RenewableTUN) Name() (string, error) {
	for {
		dev := r.peekLast()
		if dev == nil {
			if !r.waitForDevice() {
				return "", io.EOF
			}
			continue
		}
		name, err := dev.Name()
		if err == nil {
			return name, nil
		}
		if dev.IsClosed() {
			time.Sleep(1 * time.Millisecond)
			continue
		}
		return "", err
	}
}

// Events returns a channel that is fed events from the underlying tun.Device's events channel
// once it is added.
func (r *RenewableTUN) Events() <-chan tun.Event {
	return r.events
}

func (r *RenewableTUN) Close() error {
	// Attempts to set the RenewableTUN closed flag to true.
	// If it's already true, returns immediately.
	if !r.closed.CompareAndSwap(false, true) {
		return nil // already closed: idempotent
	}
	r.mu.Lock()
	devices := r.devices
	r.devices = nil
	r.cond.Broadcast()
	r.mu.Unlock()

	var lastErr error

	log.Debugf("closing %d devices", len(devices))
	for _, device := range devices {
		if err := device.Close(); err != nil {
			log.Debugf("error closing a device: %v", err)
			lastErr = err
		}
	}

	close(r.events)
	return lastErr
}

func (r *RenewableTUN) BatchSize() int {
	return 1
}

func (r *RenewableTUN) AddDevice(device tun.Device) {
	r.mu.Lock()
	if r.closed.Load() {
		r.mu.Unlock()
		_ = device.Close()
		return
	}

	var toClose *closeAwareDevice
	if len(r.devices) > 0 {
		toClose = r.devices[len(r.devices)-1]
	}

	cad := newClosableDevice(device)
	cad.redirectEvents(r.events)

	r.devices = []*closeAwareDevice{cad}
	r.cond.Broadcast()

	r.mu.Unlock()

	if toClose != nil {
		if err := toClose.Close(); err != nil {
			log.Debugf("error closing last device: %v", err)
		}
	}
}

func (r *RenewableTUN) waitForDevice() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for len(r.devices) == 0 && !r.closed.Load() {
		r.cond.Wait()
	}
	return !r.closed.Load()
}

func (r *RenewableTUN) peekLast() *closeAwareDevice {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.devices) == 0 {
		return nil
	}

	return r.devices[len(r.devices)-1]
}
