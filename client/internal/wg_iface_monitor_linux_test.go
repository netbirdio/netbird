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
	assert.True(t, restart)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deleted")

	// Other index should not trigger restart
	restart, err = inspectLinkEvent(update, "wt0", 99)
	assert.False(t, restart)
	assert.NoError(t, err)
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
	assert.True(t, restart)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "down")

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
	assert.False(t, restart)
	assert.NoError(t, err)
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
	assert.True(t, restart)
	assert.NoError(t, err)
}

func unixHeader(t uint16) unix.NlMsghdr {
	return unix.NlMsghdr{
		Type: t,
	}
}
