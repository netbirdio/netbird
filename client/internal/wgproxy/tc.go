package wgproxy

import (
	"fmt"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/vishvananda/netlink"
)

func qdiscAttrs(link netlink.Link) *netlink.GenericQdisc {
	return &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
}

func createQdisc(link netlink.Link) error {
	qdisc := qdiscAttrs(link)
	netlink.QdiscDel(qdisc)
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("netlink: replacing qdisc for %s failed: %s", link.Attrs().Name, err)
	}
	log.Infof("netlink: replacing qdisc for %s succeeded", link.Attrs().Name)
	return nil
}

func deleteQdisc(link netlink.Link) error {
	qdisc := qdiscAttrs(link)
	return netlink.QdiscDel(qdisc)
}

func filterAttrs(fd int, name string, link netlink.Link, parent uint32) *netlink.U32 {
	return &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    netlink.MakeHandle(0, 1),
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		ClassId: netlink.MakeHandle(1, 1),
		Actions: []netlink.Action{
			&netlink.BpfAction{
				Fd:   fd,
				Name: name,
			},
		},
	}
}

func createFilter(fd int, name string, link netlink.Link, parent uint32) error {
	filter := filterAttrs(fd, name, link, parent)
	err := netlink.FilterAdd(filter)
	if err != nil {
		return fmt.Errorf("failed to add filter: %s", err)
	}
	log.Infof("netlink: successfully added filter for %s", name)
	return nil
}

func deleteFilter(fd int, name string, link netlink.Link, parent uint32) error {
	filter := filterAttrs(fd, name, link, parent)
	return netlink.FilterDel(filter)
}
