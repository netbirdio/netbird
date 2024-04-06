package iface

import (
	"fmt"

	"github.com/netbirdio/netbird/iface/freebsd"
	log "github.com/sirupsen/logrus"
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

func (l *wgLink) assignAddr(address WGAddress) error {
	link, err := freebsd.LinkByName(l.name)
	if err != nil {
		return fmt.Errorf("link by name: %w", err)
	}

	ip := address.IP.String()
	mask := "0x" + address.Network.Mask.String()

	log.Infof("assign addr %s mask %s to %s interface", ip, mask, l.name)

	err = link.AssignAddr(ip, mask)
	if err != nil {
		return fmt.Errorf("assign addr: %w", err)
	}

	err = link.Up()
	if err != nil {
		return fmt.Errorf("up: %w", err)
	}

	return nil
}
