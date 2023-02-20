package android

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/iface"
)

// StateListener export for mobile
type StateListener interface {
	status.Listener
}

// WGAdapter export for mobile
type WGAdapter interface {
	iface.WGAdapter
}

type Client struct {
	sshKey    string
	privKey   string
	adminURL  string
	mgmUrl    string
	wgAdapter iface.WGAdapter
	listener  status.Listener
	recorder  *status.Status
	ctxCancel context.CancelFunc
	ctxLock   *sync.Mutex
}

func NewClient(sshKey, privateKey, adminURL, mgmURL string, wgAdapter WGAdapter) *Client {
	lvl, _ := log.ParseLevel("trace")
	log.SetLevel(lvl)

	return &Client{
		sshKey:    sshKey,
		privKey:   privateKey,
		adminURL:  adminURL,
		mgmUrl:    mgmURL,
		wgAdapter: wgAdapter,
		recorder:  status.NewRecorder(),
		ctxLock:   &sync.Mutex{},
	}
}

func (c *Client) Run() error {
	c.ctxLock.Lock()

	adminURL, err := internal.ParseURL("Admin Panel url", c.adminURL)
	if err != nil {
		return err
	}

	managementURL, err := internal.ParseURL("Management URL", c.mgmUrl)
	if err != nil {
		return err
	}

	cfg := &internal.Config{
		SSHKey:               c.sshKey,
		PrivateKey:           c.privKey,
		ManagementURL:        managementURL,
		AdminURL:             adminURL,
		WgIface:              iface.WgInterfaceDefault,
		WgPort:               iface.DefaultWgPort,
		IFaceBlackList:       []string{},
		DisableIPv6Discovery: false,
	}

	var ctx context.Context
	ctx, c.ctxCancel = context.WithCancel(context.Background())
	ctxState := internal.CtxInitState(ctx)
	c.ctxLock.Unlock()
	return internal.RunClient(ctxState, cfg, c.recorder, c.wgAdapter)
}

func (c *Client) Stop() {
	if c.ctxCancel == nil {
		return
	}

	c.ctxCancel()
}

func (c *Client) AddStatusListener(listener StateListener) {
	c.recorder.AddStatusListener(listener)
}

func (c *Client) RemoveStatusListener(listener StateListener) {
	c.recorder.RemoveStatusListener(listener)
}
