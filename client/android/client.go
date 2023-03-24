package android

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/formatter"
	"github.com/netbirdio/netbird/iface"
)

// ConnectionListener export internal Listener for mobile
type ConnectionListener interface {
	peer.Listener
}

// TunAdapter export internal TunAdapter for mobile
type TunAdapter interface {
	iface.TunAdapter
}

// IFaceDiscover export internal IFaceDiscover for mobile
type IFaceDiscover interface {
	stdnet.IFaceDiscover
}

func init() {
	formatter.SetLogcatFormatter(log.StandardLogger())
}

// Client struct manage the life circle of background service
type Client struct {
	cfgFile       string
	tunAdapter    iface.TunAdapter
	iFaceDiscover IFaceDiscover
	recorder      *peer.Status
	ctxCancel     context.CancelFunc
	ctxCancelLock *sync.Mutex
	deviceName    string
}

// NewClient instantiate a new Client
func NewClient(cfgFile, deviceName string, tunAdapter TunAdapter, iFaceDiscover IFaceDiscover) *Client {
	lvl, _ := log.ParseLevel("trace")
	log.SetLevel(lvl)

	return &Client{
		cfgFile:       cfgFile,
		deviceName:    deviceName,
		tunAdapter:    tunAdapter,
		iFaceDiscover: iFaceDiscover,
		recorder:      peer.NewRecorder(""),
		ctxCancelLock: &sync.Mutex{},
	}
}

// Run start the internal client. It is a blocker function
func (c *Client) Run(urlOpener URLOpener) error {
	cfg, err := internal.UpdateOrCreateConfig(internal.ConfigInput{
		ConfigPath: c.cfgFile,
	})
	if err != nil {
		return err
	}
	c.recorder.UpdateManagementAddress(cfg.ManagementURL.String())

	var ctx context.Context
	//nolint
	ctxWithValues := context.WithValue(context.Background(), system.DeviceNameCtxKey, c.deviceName)
	c.ctxCancelLock.Lock()
	ctx, c.ctxCancel = context.WithCancel(ctxWithValues)
	defer c.ctxCancel()
	c.ctxCancelLock.Unlock()

	auth := NewAuthWithConfig(ctx, cfg)
	err = auth.Login(urlOpener)
	if err != nil {
		return err
	}

	// todo do not throw error in case of cancelled context
	ctx = internal.CtxInitState(ctx)
	return internal.RunClient(ctx, cfg, c.recorder, c.tunAdapter, c.iFaceDiscover)
}

// Stop the internal client and free the resources
func (c *Client) Stop() {
	c.ctxCancelLock.Lock()
	defer c.ctxCancelLock.Unlock()
	if c.ctxCancel == nil {
		return
	}

	c.ctxCancel()
}

// PeersList return with the list of the PeerInfos
func (c *Client) PeersList() *PeerInfoArray {

	fullStatus := c.recorder.GetFullStatus()

	peerInfos := make([]PeerInfo, len(fullStatus.Peers))
	for n, p := range fullStatus.Peers {
		pi := PeerInfo{
			p.IP,
			p.FQDN,
			p.ConnStatus.String(),
			p.Direct,
		}
		peerInfos[n] = pi
	}

	return &PeerInfoArray{items: peerInfos}
}

// AddConnectionListener add new network connection listener
func (c *Client) AddConnectionListener(listener ConnectionListener) {
	c.recorder.AddConnectionListener(listener)
}

// RemoveConnectionListener remove connection listener
func (c *Client) RemoveConnectionListener(listener ConnectionListener) {
	c.recorder.RemoveConnectionListener(listener)
}
