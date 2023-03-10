package android

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
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

func init() {
	formatter.SetLogcatFormatter(log.StandardLogger())
}

type Client struct {
	cfgFile       string
	tunAdapter    iface.TunAdapter
	recorder      *peer.Status
	ctxCancel     context.CancelFunc
	ctxCancelLock *sync.Mutex
	deviceName    string
}

func NewClient(cfgFile, deviceName string, tunAdapter TunAdapter) *Client {
	lvl, _ := log.ParseLevel("trace")
	log.SetLevel(lvl)

	return &Client{
		cfgFile:       cfgFile,
		deviceName:    deviceName,
		tunAdapter:    tunAdapter,
		recorder:      peer.NewRecorder(),
		ctxCancelLock: &sync.Mutex{},
	}
}

func (c *Client) Run(urlOpener UrlOpener) error {
	cfg, err := internal.UpdateOrCreateConfig(internal.ConfigInput{
		ConfigPath: c.cfgFile,
	})
	if err != nil {
		return err
	}

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
	return internal.RunClient(ctx, cfg, c.recorder, c.tunAdapter)
}

func (c *Client) Stop() {
	c.ctxCancelLock.Lock()
	defer c.ctxCancelLock.Unlock()
	if c.ctxCancel == nil {
		return
	}

	c.ctxCancel()
}

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

func (c *Client) AddConnectionListener(listener ConnectionListener) {
	c.recorder.AddConnectionListener(listener)
}

func (c *Client) RemoveConnectionListener(listener ConnectionListener) {
	c.recorder.RemoveConnectionListener(listener)
}
