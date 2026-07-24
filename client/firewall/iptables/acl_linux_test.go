//go:build linux && !android

package iptables

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	nbnet "github.com/netbirdio/netbird/client/net"
)

type aclTestIface struct{}

func (aclTestIface) Name() string            { return "wt0" }
func (aclTestIface) Address() wgaddr.Address { return wgaddr.Address{} }

func TestSeedInitialEntriesUsesConnectionMarkForRedirectedTraffic(t *testing.T) {
	m := &aclManager{entries: make(map[string][][]string), optionalEntries: make(map[string][]entry)}
	m.wgIface = aclTestIface{}

	m.seedInitialEntries()
	m.seedInitialOptionalEntries()

	mark := fmt.Sprintf("%#x", nbnet.PreroutingFwmarkRedirected)
	routeMark := fmt.Sprintf("%#x", nbnet.PreroutingFwmarkMasquerade)
	assert.Contains(t, m.entries[mangleFwdKey], []string{
		"-i", "wt0", "-m", "conntrack", "--ctstate", "DNAT",
		"-m", "connmark", "!", "--mark", mark,
		"-m", "connmark", "!", "--mark", routeMark, "-j", "DROP",
	})
	assert.Equal(t, []string{"-m", "connmark", "--mark", mark, "-j", "ACCEPT"}, m.optionalEntries["FORWARD"][0].spec)
}
