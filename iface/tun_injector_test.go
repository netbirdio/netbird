package iface

import (
	"net"
	"os"
	"testing"

	"github.com/google/gopacket"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

type testInjector struct {
	skipReadPacket bool
}

func (ti testInjector) SkipReadPacket(packet gopacket.Packet) bool {
	return ti.skipReadPacket
}

func (ti testInjector) SkipWritePacket(packet gopacket.Packet) bool {
	return false
}

func TestTunInjection_Read(t *testing.T) {
	disableKernel := os.Getenv("NB_WG_KERNEL_DISABLED")
	defer os.Setenv("NB_WG_KERNEL_DISABLED", disableKernel)

	os.Setenv("NB_WG_KERNEL_DISABLED", "true")

	// Create a local UDP listener to send and receive packets
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// Create a tun device
	iface, err := tun.CreateTUN("testtun%d", unix.IFF_TUN|unix.IFF_NO_PI)
	if err != nil {
		t.Fatal(err)
	}
	defer iface.Close()

	// Create TunInjection instances with different configurations
	tests := []struct {
		name       string
		injectors  []Injector
		shouldRead bool
	}{
		{"No injectors", nil, true},
		{"SkipReadPacket: false", []Injector{testInjector{skipReadPacket: false}}, true},
		{"SkipReadPacket: true", []Injector{testInjector{skipReadPacket: true}}, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ti := &TunInjection{
				Device:    iface,
				injectors: test.injectors,
			}

			// Send a UDP packet
			_, err := pc.WriteTo([]byte("test"), pc.LocalAddr())
			if err != nil {
				t.Fatal(err)
			}

			mtu, err := iface.MTU()
			if err != nil {
				t.Fatal(err)
			}

			// Read packets from the tun device
			buf := make([]byte, mtu)
			n, err := ti.Read([][]byte{buf}, []int{mtu}, 0)
			if err != nil {
				t.Fatal(err)
			}

			// Check if the expected number of packets was read
			if test.shouldRead && n == 0 {
				t.Errorf("Expected to read a packet, but got none")
			} else if !test.shouldRead && n > 0 {
				t.Errorf("Expected no packets to be read, but got %d", n)
			}
		})
	}
}
