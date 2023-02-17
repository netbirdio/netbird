package android

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/iface"
)

// StateListener export for android
type StateListener interface {
	status.Listener
}

// WGAdapter is exists for avoid circle dependency
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
	}
}

func (c *Client) Init() error {
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
	ctxState := internal.CtxInitState(context.Background())

	return internal.RunClient(ctxState, cfg, c.recorder, c.wgAdapter)
}

func (c *Client) AddStatusListener(listener StateListener) {
	c.recorder.AddStatusListener(listener)
}

func (c *Client) RemoveStatusListener(listener StateListener) {
	c.recorder.RemoveStatusListener(listener)
}
