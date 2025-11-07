//go:build android

package device

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun"
)

// closeAwareDevice wraps a tun.Device along with a flag
// indicating whether its Close method was called.
type closeAwareDevice struct {
	isClosed atomic.Bool
	tun.Device
}

func newClosableDevice(tunDevice tun.Device) *closeAwareDevice {
	return &closeAwareDevice{
		Device:   tunDevice,
		isClosed: atomic.Bool{},
	}
}

// Close calls the underlying Device's Close method
// after setting isClosed to true.
func (c *closeAwareDevice) Close() (err error) {
	fd := c.Device.File().Fd()

	defer func() {
		if err == nil {
			log.Debugf("device %v is now closed", fd)
		} else {
			log.Debugf("error attempting to close device %v: %v", fd, err)
		}
	}()

	c.isClosed.Store(true)
	err = c.Device.Close()

	return err
}

func (c *closeAwareDevice) IsClosed() bool {
	return c.isClosed.Load()
}

type RenewableTUN struct {
	devices []*closeAwareDevice
	mu      sync.Mutex
}

func NewRenewableTUN() *RenewableTUN {
	r := &RenewableTUN{
		devices: make([]*closeAwareDevice, 0),
		mu:      sync.Mutex{},
	}

	return r
}

func (r *RenewableTUN) File() *os.File {
	log.Debug("sending device file")

	device := r.peekLast()
	if device == nil {
		return nil
	}

	return device.File()
}

func (r *RenewableTUN) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	log.Debug("reading from device")

	device := r.peekLast()
	if device == nil {
		return 0, errors.New("no available devices")
	}

	n, err = device.Read(bufs, sizes, offset)

	if err != nil {
		log.Debugf("error reading from device: %v", err)

		if device.IsClosed() {
			err = nil
		}
	} else {
		log.Debugf("read %v bytes from device %v", n, device.File().Fd())
	}

	return n, err
}

func (r *RenewableTUN) Write(bufs [][]byte, offset int) (int, error) {
	log.Debug("writing to device")

	device := r.peekLast()
	if device == nil {
		return 0, nil
	}

	n, err := device.Write(bufs, offset)

	if err != nil {
		log.Debugf("error writing to device: %v", err)

		if device.IsClosed() {
			err = nil
		}
	}

	return n, err
}

func (r *RenewableTUN) MTU() (int, error) {
	log.Debug("sending mtu")

	device := r.peekLast()
	if device == nil {
		return 0, nil
	}

	return device.MTU()
}

func (r *RenewableTUN) Name() (string, error) {
	log.Debug("sending name")

	device := r.peekLast()
	if device == nil {
		return "", nil
	}

	return device.Name()
}

func (r *RenewableTUN) Events() <-chan tun.Event {
	log.Debug("returning events channel")

	device := r.peekLast()
	if device == nil {
		return nil
	}

	return device.Events()
}

func (r *RenewableTUN) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	log.Debugf("closing %d devices", len(r.devices))

	var err error

	for _, device := range r.devices {
		err = device.Close()

		if err != nil {
			log.Debugf("error closing a device: %v", err)
		}
	}

	r.devices = r.devices[:0]

	return err
}

func (r *RenewableTUN) BatchSize() int {
	log.Debug("returning batch size")

	return 1
}

func (r *RenewableTUN) AddDevice(device tun.Device) {
	first := r.dequeue()

	// defers closing the old device after adding the new one if there was any.
	if first != nil {
		defer func(first *closeAwareDevice) {
			err := first.Close()
			if err != nil {
				log.Debugf("error closing first device: %v", err)
			}
		}(first)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.devices = append(r.devices, newClosableDevice(device))
}

func (r *RenewableTUN) peekLast() *closeAwareDevice {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.devices) == 0 {
		return nil
	}

	return r.devices[len(r.devices)-1]
}

func (r *RenewableTUN) dequeue() *closeAwareDevice {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.devices) == 0 {
		return nil
	}

	first := r.devices[0]
	r.devices = r.devices[1:]
	return first
}
