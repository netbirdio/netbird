package uspfilter

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
)

func TestLocalIPManager(t *testing.T) {
	tests := []struct {
		name      string
		setupAddr iface.WGAddress
		testIP    net.IP
		expected  bool
	}{
		{
			name: "Localhost range",
			setupAddr: iface.WGAddress{
				IP: net.ParseIP("192.168.1.1"),
				Network: &net.IPNet{
					IP:   net.ParseIP("192.168.1.0"),
					Mask: net.CIDRMask(24, 32),
				},
			},
			testIP:   net.ParseIP("127.0.0.2"),
			expected: true,
		},
		{
			name: "Localhost standard address",
			setupAddr: iface.WGAddress{
				IP: net.ParseIP("192.168.1.1"),
				Network: &net.IPNet{
					IP:   net.ParseIP("192.168.1.0"),
					Mask: net.CIDRMask(24, 32),
				},
			},
			testIP:   net.ParseIP("127.0.0.1"),
			expected: true,
		},
		{
			name: "Localhost range edge",
			setupAddr: iface.WGAddress{
				IP: net.ParseIP("192.168.1.1"),
				Network: &net.IPNet{
					IP:   net.ParseIP("192.168.1.0"),
					Mask: net.CIDRMask(24, 32),
				},
			},
			testIP:   net.ParseIP("127.255.255.255"),
			expected: true,
		},
		{
			name: "Local IP matches",
			setupAddr: iface.WGAddress{
				IP: net.ParseIP("192.168.1.1"),
				Network: &net.IPNet{
					IP:   net.ParseIP("192.168.1.0"),
					Mask: net.CIDRMask(24, 32),
				},
			},
			testIP:   net.ParseIP("192.168.1.1"),
			expected: true,
		},
		{
			name: "Local IP doesn't match",
			setupAddr: iface.WGAddress{
				IP: net.ParseIP("192.168.1.1"),
				Network: &net.IPNet{
					IP:   net.ParseIP("192.168.1.0"),
					Mask: net.CIDRMask(24, 32),
				},
			},
			testIP:   net.ParseIP("192.168.1.2"),
			expected: false,
		},
		{
			name: "IPv6 address",
			setupAddr: iface.WGAddress{
				IP: net.ParseIP("fe80::1"),
				Network: &net.IPNet{
					IP:   net.ParseIP("fe80::"),
					Mask: net.CIDRMask(64, 128),
				},
			},
			testIP:   net.ParseIP("fe80::1"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := newLocalIPManager()

			mock := &IFaceMock{
				AddressFunc: func() iface.WGAddress {
					return tt.setupAddr
				},
			}

			err := manager.UpdateLocalIPs(mock)
			require.NoError(t, err)

			result := manager.IsLocalIP(tt.testIP)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestLocalIPManager_AllInterfaces(t *testing.T) {
	manager := newLocalIPManager()
	mock := &IFaceMock{}

	// Get actual local interfaces
	interfaces, err := net.Interfaces()
	require.NoError(t, err)

	var tests []struct {
		ip       string
		expected bool
	}

	// Add all local interface IPs to test cases
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		require.NoError(t, err)

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			if ip4 := ip.To4(); ip4 != nil {
				tests = append(tests, struct {
					ip       string
					expected bool
				}{
					ip:       ip4.String(),
					expected: true,
				})
			}
		}
	}

	// Add some external IPs as negative test cases
	externalIPs := []string{
		"8.8.8.8",
		"1.1.1.1",
		"208.67.222.222",
	}
	for _, ip := range externalIPs {
		tests = append(tests, struct {
			ip       string
			expected bool
		}{
			ip:       ip,
			expected: false,
		})
	}

	require.NotEmpty(t, tests, "No test cases generated")

	err = manager.UpdateLocalIPs(mock)
	require.NoError(t, err)

	t.Logf("Testing %d IPs", len(tests))
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := manager.IsLocalIP(net.ParseIP(tt.ip))
			require.Equal(t, tt.expected, result, "IP: %s", tt.ip)
		})
	}
}

// MapImplementation is a version using map[string]struct{}
type MapImplementation struct {
	localIPs map[string]struct{}
}

func BenchmarkIPChecks(b *testing.B) {
	interfaces := make([]net.IP, 16)
	for i := range interfaces {
		interfaces[i] = net.IPv4(10, 0, byte(i>>8), byte(i))
	}

	// Setup bitmap version
	bitmapManager := &localIPManager{
		ipv4Bitmap: [1 << 16]uint32{},
	}
	for _, ip := range interfaces[:8] { // Add half of IPs
		bitmapManager.setBitmapBit(ip)
	}

	// Setup map version
	mapManager := &MapImplementation{
		localIPs: make(map[string]struct{}),
	}
	for _, ip := range interfaces[:8] {
		mapManager.localIPs[ip.String()] = struct{}{}
	}

	b.Run("Bitmap_Hit", func(b *testing.B) {
		ip := interfaces[4]
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			bitmapManager.checkBitmapBit(ip)
		}
	})

	b.Run("Bitmap_Miss", func(b *testing.B) {
		ip := interfaces[12]
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			bitmapManager.checkBitmapBit(ip)
		}
	})

	b.Run("Map_Hit", func(b *testing.B) {
		ip := interfaces[4]
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// nolint:gosimple
			_, _ = mapManager.localIPs[ip.String()]
		}
	})

	b.Run("Map_Miss", func(b *testing.B) {
		ip := interfaces[12]
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// nolint:gosimple
			_, _ = mapManager.localIPs[ip.String()]
		}
	})
}

func BenchmarkWGPosition(b *testing.B) {
	wgIP := net.ParseIP("10.10.0.1")

	// Create two managers - one checks WG IP first, other checks it last
	b.Run("WG_First", func(b *testing.B) {
		bm := &localIPManager{ipv4Bitmap: [1 << 16]uint32{}}
		bm.setBitmapBit(wgIP)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			bm.checkBitmapBit(wgIP)
		}
	})

	b.Run("WG_Last", func(b *testing.B) {
		bm := &localIPManager{ipv4Bitmap: [1 << 16]uint32{}}
		// Fill with other IPs first
		for i := 0; i < 15; i++ {
			bm.setBitmapBit(net.IPv4(10, 0, byte(i>>8), byte(i)))
		}
		bm.setBitmapBit(wgIP) // Add WG IP last
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			bm.checkBitmapBit(wgIP)
		}
	})
}
