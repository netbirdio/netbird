// Package capture provides userspace packet capture in pcap format.
//
// It taps decrypted WireGuard packets flowing through the FilteredDevice and
// writes them as pcap (readable by tcpdump, tshark, Wireshark) or as
// human-readable one-line-per-packet text.
package capture

import "io"

// Direction indicates whether a packet is entering or leaving the host.
type Direction uint8

const (
	// Inbound is a packet arriving from the network (FilteredDevice.Write path).
	Inbound Direction = iota
	// Outbound is a packet leaving the host (FilteredDevice.Read path).
	Outbound
)

// String returns "IN" or "OUT".
func (d Direction) String() string {
	if d == Outbound {
		return "OUT"
	}
	return "IN"
}

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// Options configures a capture session.
type Options struct {
	// Output receives pcap-formatted data. Nil disables pcap output.
	Output io.Writer
	// TextOutput receives human-readable packet summaries. Nil disables text output.
	TextOutput io.Writer
	// Matcher selects which packets to capture. Nil captures all.
	// Use ParseFilter("host 10.0.0.1 and tcp") or &Filter{...}.
	Matcher Matcher
	// Verbose adds seq/ack, TTL, window, total length to text output.
	Verbose bool
	// ASCII dumps transport payload as printable ASCII after each packet line.
	ASCII bool
	// SnapLen is the maximum bytes captured per packet. 0 means 65535.
	SnapLen uint32
	// BufSize is the internal channel buffer size. 0 means 256.
	BufSize int
}

// Stats reports capture session counters.
type Stats struct {
	Packets int64
	Bytes   int64
	Dropped int64
}
