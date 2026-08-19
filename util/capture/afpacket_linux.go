package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// htons converts a uint16 from host to network (big-endian) byte order.
func htons(v uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return binary.NativeEndian.Uint16(buf[:])
}

// AFPacketCapture reads raw packets from a network interface using an
// AF_PACKET socket. This is the kernel-mode fallback when FilteredDevice is
// not available (kernel WireGuard). Linux only.
//
// It implements device.PacketCapture so it can be set on a Session, but it
// drives its own read loop rather than being called from FilteredDevice.
// Call Start to begin and Stop to end.
type AFPacketCapture struct {
	ifaceName string
	sess      *Session
	fd        int
	mu        sync.Mutex
	stopped   chan struct{}
	started   atomic.Bool
	closed    atomic.Bool
}

// NewAFPacketCapture creates a capture bound to the given interface.
// The session receives packets via Offer.
func NewAFPacketCapture(ifaceName string, sess *Session) *AFPacketCapture {
	return &AFPacketCapture{
		ifaceName: ifaceName,
		sess:      sess,
		fd:        -1,
		stopped:   make(chan struct{}),
	}
}

// Start opens the AF_PACKET socket and begins reading packets.
// Packets are fed to the session via Offer. Returns immediately;
// the read loop runs in a goroutine.
func (c *AFPacketCapture) Start() error {
	if c.sess == nil {
		return errors.New("nil capture session")
	}
	if !c.started.CompareAndSwap(false, true) {
		return errors.New("capture already started")
	}
	if c.closed.Load() {
		c.started.Store(false)
		return errors.New("cannot restart stopped capture")
	}

	iface, err := net.InterfaceByName(c.ifaceName)
	if err != nil {
		c.started.Store(false)
		return fmt.Errorf("interface %s: %w", c.ifaceName, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		c.started.Store(false)
		return fmt.Errorf("create AF_PACKET socket: %w", err)
	}

	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		c.started.Store(false)
		return fmt.Errorf("bind to %s: %w", c.ifaceName, err)
	}

	c.mu.Lock()
	c.fd = fd
	c.mu.Unlock()

	go c.readLoop(fd)
	return nil
}

// Stop closes the socket and waits for the read loop to exit. Idempotent.
func (c *AFPacketCapture) Stop() {
	if !c.closed.CompareAndSwap(false, true) {
		if c.started.Load() {
			<-c.stopped
		}
		return
	}

	c.mu.Lock()
	fd := c.fd
	c.fd = -1
	c.mu.Unlock()

	if fd >= 0 {
		unix.Close(fd)
	}

	if c.started.Load() {
		<-c.stopped
	}
}

func (c *AFPacketCapture) readLoop(fd int) {
	defer close(c.stopped)

	buf := make([]byte, 65536)
	pollFds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}

	for {
		if c.closed.Load() {
			return
		}

		ok, err := c.pollOnce(pollFds)
		if err != nil {
			return
		}
		if !ok {
			continue
		}

		c.recvAndOffer(fd, buf)
	}
}

// pollOnce waits for data on the fd. Returns true if data is ready, false for timeout/retry.
// Returns an error to signal the loop should exit.
func (c *AFPacketCapture) pollOnce(pollFds []unix.PollFd) (bool, error) {
	n, err := unix.Poll(pollFds, 200)
	if err != nil {
		if errors.Is(err, unix.EINTR) {
			return false, nil
		}
		if c.closed.Load() {
			return false, errors.New("closed")
		}
		log.Debugf("af_packet poll: %v", err)
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if pollFds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
		return false, errors.New("fd error")
	}
	return true, nil
}

func (c *AFPacketCapture) recvAndOffer(fd int, buf []byte) {
	nr, from, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return
		}
		if !c.closed.Load() {
			log.Debugf("af_packet recvfrom: %v", err)
		}
		return
	}
	if nr < 1 {
		return
	}

	ver := buf[0] >> 4
	if ver != 4 && ver != 6 {
		return
	}

	// The kernel sets Pkttype on AF_PACKET sockets:
	//   PACKET_HOST(0)     = addressed to us (inbound)
	//   PACKET_OUTGOING(4) = sent by us (outbound)
	outbound := false
	if sa, ok := from.(*unix.SockaddrLinklayer); ok {
		outbound = sa.Pkttype == unix.PACKET_OUTGOING
	}
	c.sess.Offer(buf[:nr], outbound)
}

// Offer satisfies device.PacketCapture but is unused: the AFPacketCapture
// drives its own read loop. This exists only so the type signature is
// compatible if someone tries to set it as a PacketCapture.
func (c *AFPacketCapture) Offer([]byte, bool) {
	// unused: AFPacketCapture drives its own read loop
}
