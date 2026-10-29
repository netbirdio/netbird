package device

import (
	"fmt"
	"os/exec"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/freebsd"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type wgLink struct {
	name string
	link *freebsd.Link
}

func newWGLink(name string) *wgLink {
	link := freebsd.NewLink(name)

	return &wgLink{
		name: name,
		link: link,
	}
}

// Type returns the interface type
func (l *wgLink) Type() string {
	return "wireguard"
}

// Close deletes the link interface
func (l *wgLink) Close() error {
	return l.link.Del()
}

func (l *wgLink) recreate() error {
	if err := l.link.Recreate(); err != nil {
		return fmt.Errorf("recreate: %w", err)
	}

	return nil
}

func (l *wgLink) setMTU(mtu int) error {
	if err := l.link.SetMTU(mtu); err != nil {
		return fmt.Errorf("set mtu: %w", err)
	}

	return nil
}

func (l *wgLink) up() error {
	if err := l.link.Up(); err != nil {
		return fmt.Errorf("up: %w", err)
	}

	return nil
}

func (l *wgLink) assignAddr(address *wgaddr.Address) error {
	link, err := freebsd.LinkByName(l.name)
	if err != nil {
		return fmt.Errorf("link by name: %w", err)
	}

	prefixLen := address.Network.Bits()
	maskBits := uint32(0xffffffff) << (32 - prefixLen)
	mask := fmt.Sprintf("0x%08x", maskBits)

	log.Infof("assign addr %s mask %s to %s interface", address.IP, mask, l.name)

	if err := link.AssignAddr(address.IP.String(), mask); err != nil {
		return fmt.Errorf("assign addr: %w", err)
	}

	if address.HasIPv6() {
		log.Infof("assign IPv6 addr %s to %s interface", address.IPv6String(), l.name)
		cmd := exec.Command("ifconfig", l.name, "inet6", address.IPv6String())
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warnf("failed to assign IPv6 address %s to %s, continuing v4-only: %s: %v", address.IPv6String(), l.name, string(out), err)
			address.ClearIPv6()
		}
	}

	if err := link.Up(); err != nil {
		return fmt.Errorf("up: %w", err)
	}

	return nil
}
