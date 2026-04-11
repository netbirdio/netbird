package inspect

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

// PROXY protocol v2 constants (RFC 7239 / HAProxy spec)
var proxyV2Signature = [12]byte{
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51,
	0x55, 0x49, 0x54, 0x0A,
}

const (
	proxyV2VersionCommand = 0x21 // version 2, PROXY command
	proxyV2FamilyTCP4     = 0x11 // AF_INET, STREAM
	proxyV2FamilyTCP6     = 0x21 // AF_INET6, STREAM
)

// forwardToEnvoy forwards a connection to the given envoy sidecar via PROXY protocol v2.
// The caller provides the envoy manager snapshot to avoid accessing p.envoy without lock.
func (p *Proxy) forwardToEnvoy(ctx context.Context, pconn *peekConn, dst netip.AddrPort, src SourceInfo, em *envoyManager) error {
	envoyAddr := em.ListenAddr()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", envoyAddr.String())
	if err != nil {
		return fmt.Errorf("dial envoy at %s: %w", envoyAddr, err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			p.log.Debugf("close envoy conn: %v", err)
		}
	}()

	if err := writeProxyV2Header(conn, src.IP, dst); err != nil {
		return fmt.Errorf("write PROXY v2 header: %w", err)
	}

	p.log.Tracef("envoy: forwarded %s -> %s via PROXY v2", src.IP, dst)

	return relay(ctx, pconn, conn)
}

// writeProxyV2Header writes a PROXY protocol v2 header to w.
// The header encodes the original source IP and the destination address:port.
func writeProxyV2Header(w net.Conn, srcIP netip.Addr, dst netip.AddrPort) error {
	srcIP = srcIP.Unmap()
	dstIP := dst.Addr().Unmap()

	var (
		family byte
		addrs  []byte
	)

	if srcIP.Is4() && dstIP.Is4() {
		family = proxyV2FamilyTCP4
		s4 := srcIP.As4()
		d4 := dstIP.As4()
		addrs = make([]byte, 12) // 4+4+2+2
		copy(addrs[0:4], s4[:])
		copy(addrs[4:8], d4[:])
		binary.BigEndian.PutUint16(addrs[8:10], 0) // src port unknown
		binary.BigEndian.PutUint16(addrs[10:12], dst.Port())
	} else {
		family = proxyV2FamilyTCP6
		s16 := srcIP.As16()
		d16 := dstIP.As16()
		addrs = make([]byte, 36) // 16+16+2+2
		copy(addrs[0:16], s16[:])
		copy(addrs[16:32], d16[:])
		binary.BigEndian.PutUint16(addrs[32:34], 0) // src port unknown
		binary.BigEndian.PutUint16(addrs[34:36], dst.Port())
	}

	// Header: signature(12) + ver_cmd(1) + family(1) + len(2) + addrs
	header := make([]byte, 16+len(addrs))
	copy(header[0:12], proxyV2Signature[:])
	header[12] = proxyV2VersionCommand
	header[13] = family
	binary.BigEndian.PutUint16(header[14:16], uint16(len(addrs)))
	copy(header[16:], addrs)

	_, err := w.Write(header)
	return err
}
