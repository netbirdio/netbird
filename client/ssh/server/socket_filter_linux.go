//go:build linux

package server

import (
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// SockFprog represents a BPF program for socket filtering
type SockFprog struct {
	Len    uint16
	Filter *unix.SockFilter
}

// filterInfo stores the file descriptor and filter state for each listener
type filterInfo struct {
	fd   int
	file *os.File
}

var (
	listenerFilters = make(map[*net.TCPListener]*filterInfo)
	filterMutex     sync.RWMutex
)

// attachSocketFilter attaches a BPF socket filter to restrict SSH connections
// to only the specified WireGuard interface index
func attachSocketFilter(listener net.Listener, wgIfIndex int) error {
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		return fmt.Errorf("listener is not a TCP listener")
	}

	file, err := tcpListener.File()
	if err != nil {
		return fmt.Errorf("get listener file descriptor: %w", err)
	}
	// Don't close the file here - we need it for detaching the filter

	// Set the duplicated FD to non-blocking to match the mode of the
	// FD used by the Go runtime's network poller
	if err := syscall.SetNonblock(int(file.Fd()), true); err != nil {
		file.Close()
		return fmt.Errorf("set non-blocking on duplicated FD: %w", err)
	}

	// Create BPF program that filters by interface index
	prog, err := createInterfaceFilterProgram(uint32(wgIfIndex))
	if err != nil {
		file.Close()
		return fmt.Errorf("create BPF program: %w", err)
	}

	assembled, err := bpf.Assemble(prog)
	if err != nil {
		file.Close()
		return fmt.Errorf("assemble BPF program: %w", err)
	}

	// Convert to unix.SockFilter format
	sockFilters := make([]unix.SockFilter, len(assembled))
	for i, raw := range assembled {
		sockFilters[i] = unix.SockFilter{
			Code: raw.Op,
			Jt:   raw.Jt,
			Jf:   raw.Jf,
			K:    raw.K,
		}
	}

	// Attach socket filter to the TCP listener
	sockFprog := &SockFprog{
		Len:    uint16(len(sockFilters)),
		Filter: &sockFilters[0],
	}

	fd := int(file.Fd())
	_, _, errno := syscall.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_SOCKET),
		uintptr(unix.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(sockFprog)),
		unsafe.Sizeof(*sockFprog),
		0,
	)
	if errno != 0 {
		file.Close()
		return fmt.Errorf("attach socket filter: %v", errno)
	}

	// Store the file descriptor and file for later detach
	filterMutex.Lock()
	listenerFilters[tcpListener] = &filterInfo{
		fd:   fd,
		file: file,
	}
	filterMutex.Unlock()

	log.Debugf("SSH socket filter attached: restricting to interface index %d", wgIfIndex)
	return nil
}

// createInterfaceFilterProgram creates a BPF program that accepts packets
// only from the specified interface index
func createInterfaceFilterProgram(wgIfIndex uint32) ([]bpf.Instruction, error) {
	return []bpf.Instruction{
		// Load interface index from socket metadata
		// ExtInterfaceIndex is a special BPF extension for interface index
		bpf.LoadExtension{Num: bpf.ExtInterfaceIndex},

		// Compare with WireGuard interface index
		bpf.JumpIf{
			Cond:     bpf.JumpEqual,
			Val:      wgIfIndex,
			SkipTrue: 1,
		},

		// Reject if not matching (return 0)
		bpf.RetConstant{Val: 0},

		// Accept if matching (return maximum packet size)
		bpf.RetConstant{Val: 0xFFFFFFFF},
	}, nil
}

// detachSocketFilter removes the socket filter from a TCP listener
func detachSocketFilter(listener net.Listener) error {
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		return fmt.Errorf("listener is not a TCP listener")
	}

	filterMutex.Lock()
	info, exists := listenerFilters[tcpListener]
	if exists {
		delete(listenerFilters, tcpListener)
	}
	filterMutex.Unlock()

	if !exists {
		log.Debugf("No socket filter attached to detach")
		return nil
	}

	defer func() {
		if closeErr := info.file.Close(); closeErr != nil {
			log.Debugf("listener file close error: %v", closeErr)
		}
	}()

	// Use the same file descriptor that was used for attach
	if err := unix.SetsockoptInt(info.fd, unix.SOL_SOCKET, unix.SO_DETACH_FILTER, 0); err != nil {
		return fmt.Errorf("detach socket filter: %w", err)
	}

	log.Debugf("SSH socket filter detached")
	return nil
}
