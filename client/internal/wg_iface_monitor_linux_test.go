//go:build linux

package internal

import (
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestInspectLinkEvent_DelLink(t *testing.T) {
	update := netlink.LinkUpdate{
		Header: unixHeader(syscall.RTM_DELLINK),
		Link:   &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Index: 42, Name: "wt0"}},
	}
	update.Index = 42

	restart, err := inspectLinkEvent(update, "wt0", 42)
	assert.True(t, restart, "DELLINK on tracked interface should trigger restart")
	require.Error(t, err, "DELLINK should return an error")
	assert.Contains(t, err.Error(), "deleted", "error should mention deleted")

	// Other index should not trigger restart
	restart, err = inspectLinkEvent(update, "wt0", 99)
	assert.False(t, restart, "DELLINK on unrelated interface should not trigger restart")
	assert.NoError(t, err, "unrelated DELLINK should have no error")
}

func TestInspectLinkEvent_NewLink_Down(t *testing.T) {
	// Same index, same name, but FlagUp is not set
	attrs := netlink.LinkAttrs{
		Index: 42,
		Name:  "wt0",
		Flags: 0, // FlagUp cleared
	}
	update := netlink.LinkUpdate{
		Header: unixHeader(syscall.RTM_NEWLINK),
		Link:   &netlink.GenericLink{LinkAttrs: attrs},
	}
	update.Index = 42

	restart, err := inspectLinkEvent(update, "wt0", 42)
	assert.True(t, restart, "NEWLINK with FlagUp cleared should trigger restart")
	require.Error(t, err, "NEWLINK with FlagUp cleared should return an error")
	assert.Contains(t, err.Error(), "down", "error should describe link as down")

	// Same index, same name, with FlagUp set should be ignored
	attrsUp := netlink.LinkAttrs{
		Index: 42,
		Name:  "wt0",
		Flags: net.FlagUp,
	}
	updateUp := netlink.LinkUpdate{
		Header: unixHeader(syscall.RTM_NEWLINK),
		Link:   &netlink.GenericLink{LinkAttrs: attrsUp},
	}
	updateUp.Index = 42

	restart, err = inspectLinkEvent(updateUp, "wt0", 42)
	assert.False(t, restart, "NEWLINK with FlagUp set should not trigger restart")
	assert.NoError(t, err, "normal up link should produce no error")
}

func TestInspectLinkEvent_NewLink_Recreated(t *testing.T) {
	// Recreated at different index
	attrs := netlink.LinkAttrs{
		Index: 99,
		Name:  "wt0",
		Flags: net.FlagUp,
	}
	update := netlink.LinkUpdate{
		Header: unixHeader(syscall.RTM_NEWLINK),
		Link:   &netlink.GenericLink{LinkAttrs: attrs},
	}
	update.Index = 99

	restart, err := inspectLinkEvent(update, "wt0", 42)
	assert.True(t, restart, "recreated interface with new index should trigger restart")
	assert.NoError(t, err, "recreation should return nil error")
}

func TestInspectLinkEvent_NewLink_Renamed(t *testing.T) {
	// Same index, but interface was renamed
	attrs := netlink.LinkAttrs{
		Index: 42,
		Name:  "renamed0",
		Flags: net.FlagUp,
	}
	update := netlink.LinkUpdate{
		Header: unixHeader(syscall.RTM_NEWLINK),
		Link:   &netlink.GenericLink{LinkAttrs: attrs},
	}
	update.Index = 42

	restart, err := inspectLinkEvent(update, "wt0", 42)
	assert.True(t, restart, "renamed interface at tracked index should trigger restart")
	require.Error(t, err, "renamed interface should return an error")
	assert.Contains(t, err.Error(), "renamed", "error should mention renamed")
}

func unixHeader(t uint16) unix.NlMsghdr {
	return unix.NlMsghdr{
		Type: t,
	}
}
