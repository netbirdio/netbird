package internal

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"syscall"

	log "github.com/sirupsen/logrus"
)

const (
	SO_ATTACH_BPF    int    = 50
	SO_ATTACH_FILTER int    = 26
	StunMagicCookie  uint32 = 0x2112A442
)

type SharedUDPConn struct {
	fd        int
	localAddr net.UDPAddr
}

func (conn *SharedUDPConn) LocalAddr() net.Addr {

	return &conn.localAddr
}

func (conn *SharedUDPConn) ReadFrom(buf []byte) (n int, addr net.Addr, err error) {
	n, rAddr, err := syscall.Recvfrom(conn.fd, buf, 0)
	if err != nil {
		return -1, nil, err
	}

	rAddrIn4, ok := rAddr.(*syscall.SockaddrInet4)
	if !ok {
		return -1, nil, fmt.Errorf("invalid address type")
	}

	packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})

	transport := packet.TransportLayer()
	if transport == nil {
		return -1, nil, fmt.Errorf("failed to decode packet")
	}
	udp, ok := transport.(*layers.UDP)
	if !ok {
		return -1, nil, fmt.Errorf("invalid layer type")
	}
	payload := packet.ApplicationLayer()

	rUDPAddr := &net.UDPAddr{
		IP:   rAddrIn4.Addr[:],
		Port: int(udp.SrcPort),
	}

	n = len(payload.Payload())

	copy(buf[:n], payload.Payload()[:])

	log.Tracef("ReadFrom: ra=%s, len=%d, buf=%s", rUDPAddr, n, hex.EncodeToString(buf[:n]))

	return n, rUDPAddr, nil
}

func (conn *SharedUDPConn) WriteTo(buf []byte, rAddr net.Addr) (n int, err error) {
	rUDPAddr, ok := rAddr.(*net.UDPAddr)
	if !ok {
		return -1, fmt.Errorf("invalid address type")
	}

	rSockAddr := &syscall.SockaddrInet4{
		Port: 0,
	}
	copy(rSockAddr.Addr[:], rUDPAddr.IP.To4())

	buffer := gopacket.NewSerializeBuffer()
	payload := gopacket.Payload(buf)
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    conn.localAddr.IP,
		DstIP:    rUDPAddr.IP,
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(conn.localAddr.Port),
		DstPort: layers.UDPPort(rUDPAddr.Port),
	}
	udp.SetNetworkLayerForChecksum(ip)
	seropts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buffer, seropts, udp, payload); err != nil {
		return -1, fmt.Errorf("failed serialize packet: %s", err)
	}

	syscall.Sendto(conn.fd, buffer.Bytes(), 0, rSockAddr)

	return 0, nil
}

func (conn *SharedUDPConn) Close() error {
	return nil // TODO
}

func (conn *SharedUDPConn) SetDeadline(tm time.Time) error {
	return nil
}

func (conn *SharedUDPConn) SetReadDeadline(tm time.Time) error {
	return nil
}

func (conn *SharedUDPConn) SetWriteDeadline(tm time.Time) error {
	return nil
}

func NewSharedConn(lAddr net.UDPAddr) (conn *SharedUDPConn, err error) {
	conn = &SharedUDPConn{
		localAddr: lAddr,
	}

	// Open a raw socket
	conn.fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		panic(err)
	}

	spec := ebpf.ProgramSpec{
		Type:    ebpf.SocketFilter,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1), // LDABS requires ctx in R6
			asm.LoadAbs(-0x100000+22, asm.Half),
			asm.JNE.Imm(asm.R0, int32(lAddr.Port), "skip"),
			asm.LoadAbs(-0x100000+32, asm.Word),
			asm.JNE.Imm(asm.R0, int32(StunMagicCookie), "skip"),
			asm.Mov.Imm(asm.R0, -1).Sym("exit"),
			asm.Return(),
			asm.Mov.Imm(asm.R0, 0).Sym("skip"),
			asm.Return(),
		},
	}

	fmt.Printf("Instructions:\n%v\n", spec.Instructions)

	prog, err := ebpf.NewProgramWithOptions(&spec, ebpf.ProgramOptions{
		LogLevel: 6, // TODO take configured log-level from args
	})
	if err != nil {
		panic(err)
	}

	if err := syscall.SetsockoptInt(conn.fd, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD()); err != nil {

	}

	return conn, nil
}
