//go:build linux
// +build linux

package iface

import (
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func DestroyInterface(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		log.Errorf("failed to get link by name %s: %v", name, err)
		return err
	}

	if err := netlink.LinkDel(link); err != nil {
		log.Errorf("failed to delete link %s: %v", name, err)
		return err
	}

	log.Infof("interface %s successfully deleted", name)
	return nil
}
