//go:build linux || darwin

package tun

import (
	"net"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

type Proxy struct {
	Device       *Device
	PConn        net.PacketConn
	DstAddr      net.Addr
	shutdownFlag atomic.Bool
}

func (p *Proxy) Start() {
	go p.readFromDevice()
	go p.readFromConn()
}

func (p *Proxy) Close() {
	p.shutdownFlag.Store(true)
}

func (p *Proxy) readFromDevice() {
	buf := make([]byte, 1500)
	for {
		n, err := p.Device.Read(buf)
		if err != nil {
			if p.shutdownFlag.Load() {
				return
			}
			log.Errorf("failed to read from device: %s", err)
			return
		}

		_, err = p.PConn.WriteTo(buf[:n], p.DstAddr)
		if err != nil {
			if p.shutdownFlag.Load() {
				return
			}
			log.Errorf("failed to write to conn: %s", err)
			return
		}
	}
}

func (p *Proxy) readFromConn() {
	buf := make([]byte, 1500)
	for {
		n, _, err := p.PConn.ReadFrom(buf)
		if err != nil {
			if p.shutdownFlag.Load() {
				return
			}
			log.Errorf("failed to read from conn: %s", err)
			return
		}

		_, err = p.Device.Write(buf[:n])
		if err != nil {
			if p.shutdownFlag.Load() {
				return
			}
			log.Errorf("failed to write to device: %s", err)
			return
		}
	}
}
