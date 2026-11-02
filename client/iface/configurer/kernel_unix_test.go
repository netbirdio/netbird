//go:build (linux && !android) || freebsd

package configurer

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeWGClient struct {
	configureErr error
	deviceErr    error
	calls        int
	closed       bool
}

type fakeWGClientFactory struct {
	openErr error
	clients []*fakeWGClient
}

func (f *fakeWGClient) Device(string) (*wgtypes.Device, error) {
	f.calls++
	if f.deviceErr != nil {
		return nil, f.deviceErr
	}
	return &wgtypes.Device{}, nil
}

func (f *fakeWGClient) ConfigureDevice(string, wgtypes.Config) error {
	f.calls++
	return f.configureErr
}

func (f *fakeWGClient) Close() error {
	f.closed = true
	return nil
}

func (f *fakeWGClientFactory) open() (wgClient, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	client := &fakeWGClient{}
	f.clients = append(f.clients, client)
	return client, nil
}

func TestKernelConfigurer_ReusesClientAcrossRequests(t *testing.T) {
	c, factory := newFakeKernelConfigurer()
	peerKey := testPeerKey(t)

	require.NoError(t, c.RemovePeer(peerKey))
	require.NoError(t, c.RemovePeer(peerKey))
	_, err := c.FullStats()
	require.NoError(t, err)

	require.Len(t, factory.clients, 1, "all requests should share one client")
	assert.Equal(t, 3, factory.clients[0].calls, "every request should go through the shared client")
	assert.False(t, factory.clients[0].closed, "a healthy client should stay open")
}

func TestKernelConfigurer_ReopensClientAfterFailedConfigure(t *testing.T) {
	c, factory := newFakeKernelConfigurer()
	peerKey := testPeerKey(t)

	require.NoError(t, c.RemovePeer(peerKey))
	require.Len(t, factory.clients, 1)

	factory.clients[0].configureErr = errors.New("netlink down")
	require.Error(t, c.RemovePeer(peerKey))
	assert.True(t, factory.clients[0].closed, "the failed client should be closed")
	assert.Len(t, factory.clients, 1, "a failure must not open a client on its own")

	require.NoError(t, c.RemovePeer(peerKey))
	require.Len(t, factory.clients, 2, "the next request should open a fresh client")
	assert.Equal(t, 1, factory.clients[1].calls, "the request should run on the fresh client")
	assert.False(t, factory.clients[1].closed, "the fresh client should stay open")
}

func TestKernelConfigurer_ReopensClientAfterFailedDeviceQuery(t *testing.T) {
	c, factory := newFakeKernelConfigurer()

	_, err := c.FullStats()
	require.NoError(t, err)
	require.Len(t, factory.clients, 1)

	factory.clients[0].deviceErr = errors.New("netlink down")
	_, err = c.FullStats()
	require.Error(t, err)
	assert.True(t, factory.clients[0].closed, "the failed client should be closed")

	_, err = c.FullStats()
	require.NoError(t, err)
	assert.Len(t, factory.clients, 2, "the next request should open a fresh client")
}

func TestKernelConfigurer_RetriesOpenOnNextRequest(t *testing.T) {
	c, factory := newFakeKernelConfigurer()
	peerKey := testPeerKey(t)

	factory.openErr = errors.New("no netlink")
	require.Error(t, c.RemovePeer(peerKey))
	assert.Empty(t, factory.clients, "a failed open leaves no client behind")

	factory.openErr = nil
	require.NoError(t, c.RemovePeer(peerKey))
	assert.Len(t, factory.clients, 1, "the next request should open the client")
}

func TestKernelConfigurer_CloseRejectsFurtherRequests(t *testing.T) {
	c, factory := newFakeKernelConfigurer()
	peerKey := testPeerKey(t)

	require.NoError(t, c.RemovePeer(peerKey))
	require.Len(t, factory.clients, 1)

	c.Close()
	c.Close()
	assert.True(t, factory.clients[0].closed, "Close should release the client")

	require.ErrorIs(t, c.RemovePeer(peerKey), errConfigurerClosed)
	_, err := c.FullStats()
	require.ErrorIs(t, err, errConfigurerClosed)
	assert.Len(t, factory.clients, 1, "a closed configurer must not open a client")
}

func TestKernelConfigurer_ConcurrentRequestsShareOneClient(t *testing.T) {
	c, factory := newFakeKernelConfigurer()
	peerKey := testPeerKey(t)

	const workers = 16
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- c.RemovePeer(peerKey)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	require.Len(t, factory.clients, 1, "concurrent requests should share one client")
	assert.Equal(t, workers, factory.clients[0].calls, "every request should reach the shared client")
}

func newFakeKernelConfigurer() (*KernelConfigurer, *fakeWGClientFactory) {
	factory := &fakeWGClientFactory{}
	return newKernelConfigurer("wt0", factory.open), factory
}

func testPeerKey(t *testing.T) string {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return key.PublicKey().String()
}
