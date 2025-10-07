package device

import (
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun"
	"os"
)

type RenewableTUN struct {
	devices []tun.Device
}

func (r *RenewableTUN) File() *os.File {
	log.Debug("sending device file.")
	return r.peekLast().File()
}

func (r *RenewableTUN) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	log.Debug("reading from device.")
	n, err = r.peekLast().Read(bufs, sizes, offset)

	if err != nil {
		log.Debugf("error reading from device: %v", err)
	}

	return n, nil
}

func (r *RenewableTUN) Write(bufs [][]byte, offset int) (int, error) {
	log.Debug("writing to device.")
	n, err := r.peekLast().Write(bufs, offset)

	if err != nil {
		log.Debugf("error writing to device: %v", err)
	}

	return n, nil
}

func (r *RenewableTUN) MTU() (int, error) {
	log.Debug("sending mtu.")
	return r.peekLast().MTU()
}

func (r *RenewableTUN) Name() (string, error) {
	log.Debug("sending name.")
	return r.peekLast().Name()
}

func (r *RenewableTUN) Events() <-chan tun.Event {
	log.Debug("returning events channel.")
	return r.peekLast().Events()
}

func (r *RenewableTUN) Close() error {
	log.Debug("closing.")

	var err error

	for _, device := range r.devices {
		err = device.Close()
	}

	clear(r.devices)

	return err
}

func (r *RenewableTUN) BatchSize() int {
	log.Debug("returning batch size.")

	return 1
}

func (r *RenewableTUN) addDevice(device tun.Device) {
	first := r.dequeue()

	if first != nil {
		defer func(first tun.Device) {
			err := first.Close()
			if err != nil {
				log.Debug("Error closing first device.")
			}
		}(first)
	}

	r.devices = append(r.devices, device)
}

func (r *RenewableTUN) peekLast() tun.Device {
	//r.mu.Lock()
	//defer r.mu.Unlock()

	if len(r.devices) == 0 {
		return nil
	}

	return r.devices[len(r.devices)-1]
}

func (r *RenewableTUN) peek() tun.Device {
	//r.mu.Lock()
	//defer r.mu.Unlock()
	if len(r.devices) == 0 {
		return nil
	}

	return r.devices[0]
}

func (r *RenewableTUN) dequeue() tun.Device {
	//r.mu.Lock()
	//defer r.mu.Unlock()

	if len(r.devices) == 0 {
		return nil
	}

	first := r.devices[0]
	r.devices = r.devices[1:]
	return first
}

func NewRenewableTUN() *RenewableTUN {
	r := &RenewableTUN{
		devices: make([]tun.Device, 0),
	}

	return r
}
