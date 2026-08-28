package stdnet

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/pion/transport/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countingDiscover struct {
	calls int
	list  []*transport.Interface
	err   error
}

func (d *countingDiscover) iFaces() ([]*transport.Interface, error) {
	d.calls++
	if d.err != nil {
		return nil, d.err
	}
	return d.list, nil
}

func newTestNet(t *testing.T, d iFaceDiscover) *Net {
	t.Helper()
	return &Net{
		iFaceDiscover: d,
		ctx:           context.Background(),
	}
}

func testIFace(index int, name string) *transport.Interface {
	return transport.NewInterface(net.Interface{Index: index, Name: name})
}

func TestNet_InterfacesDiscoversLazilyAndCaches(t *testing.T) {
	d := &countingDiscover{list: []*transport.Interface{testIFace(1, "eth0")}}
	n := newTestNet(t, d)

	require.Zero(t, d.calls, "construction must not discover interfaces")

	iFaces, err := n.Interfaces()
	require.NoError(t, err)
	require.Len(t, iFaces, 1)
	assert.Equal(t, 1, d.calls)

	_, err = n.Interfaces()
	require.NoError(t, err)
	assert.Equal(t, 1, d.calls)
}

func TestNet_InterfacesRetryAfterDiscoveryFailure(t *testing.T) {
	discoverErr := errors.New("discover failed")
	d := &countingDiscover{err: discoverErr}
	n := newTestNet(t, d)

	_, err := n.Interfaces()
	require.ErrorIs(t, err, discoverErr)

	d.err = nil
	d.list = []*transport.Interface{testIFace(1, "eth0")}

	iFaces, err := n.Interfaces()
	require.NoError(t, err)
	require.Len(t, iFaces, 1)
	assert.Equal(t, 2, d.calls)
}

func TestNet_InterfaceByNameRefreshes(t *testing.T) {
	d := &countingDiscover{list: []*transport.Interface{testIFace(3, "eth0")}}
	n := newTestNet(t, d)

	ifc, err := n.InterfaceByName("eth0")
	require.NoError(t, err)
	assert.Equal(t, "eth0", ifc.Name)
	assert.Equal(t, 1, d.calls)

	_, err = n.InterfaceByName("nope")
	require.ErrorIs(t, err, transport.ErrInterfaceNotFound)
}

func TestNet_InterfaceByIndexRefreshes(t *testing.T) {
	d := &countingDiscover{list: []*transport.Interface{testIFace(3, "eth0")}}
	n := newTestNet(t, d)

	ifc, err := n.InterfaceByIndex(3)
	require.NoError(t, err)
	assert.Equal(t, "eth0", ifc.Name)
	assert.Equal(t, 1, d.calls)

	_, err = n.InterfaceByIndex(99)
	require.ErrorIs(t, err, transport.ErrInterfaceNotFound)
}

func TestNet_InterfaceLookupPropagatesDiscoveryError(t *testing.T) {
	discoverErr := errors.New("discover failed")
	n := newTestNet(t, &countingDiscover{err: discoverErr})

	_, err := n.InterfaceByName("eth0")
	require.ErrorIs(t, err, discoverErr)

	_, err = n.InterfaceByIndex(1)
	require.ErrorIs(t, err, discoverErr)
}

func TestNet_InterfacesReturnsCopy(t *testing.T) {
	d := &countingDiscover{list: []*transport.Interface{testIFace(1, "eth0")}}
	n := newTestNet(t, d)

	iFaces, err := n.Interfaces()
	require.NoError(t, err)
	require.Len(t, iFaces, 1)

	iFaces[0] = testIFace(2, "tampered")

	iFaces, err = n.Interfaces()
	require.NoError(t, err)
	require.Len(t, iFaces, 1)
	assert.Equal(t, "eth0", iFaces[0].Name)
}
