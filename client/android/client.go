package android

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/cmd"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/iface"
)

// ConnectionListener export for mobile
type ConnectionListener interface {
	status.Listener
}

// WGAdapter export for mobile
type WGAdapter interface {
	iface.WGAdapter
}

type UrlOpener interface {
	Open(string)
}

type Client struct {
	cfgFile   string
	adminURL  string
	mgmUrl    string
	wgAdapter iface.WGAdapter
	recorder  *status.Status
	ctxCancel context.CancelFunc
	ctxLock   *sync.Mutex
	urlOpener UrlOpener
}

func NewClient(cfgFile, adminURL, mgmURL string, wgAdapter WGAdapter, urlOpener UrlOpener) *Client {
	lvl, _ := log.ParseLevel("trace")
	log.SetLevel(lvl)

	return &Client{
		cfgFile:   cfgFile,
		adminURL:  adminURL,
		mgmUrl:    mgmURL,
		wgAdapter: wgAdapter,
		urlOpener: urlOpener,
		recorder:  status.NewRecorder(),
		ctxLock:   &sync.Mutex{},
	}
}

func (c *Client) Run() error {
	c.ctxLock.Lock()

	cfg, err := internal.GetConfig(internal.ConfigInput{
		ManagementURL: c.mgmUrl,
		AdminURL:      c.adminURL,
		ConfigPath:    c.cfgFile,
	})

	ctx := context.Background()

	err = c.login(ctx, cfg, "")
	if err != nil {
		return fmt.Errorf("foreground login failed: %v", err)
	}

	ctx, c.ctxCancel = context.WithCancel(ctx)
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

func (c *Client) AddConnectionListener(listener ConnectionListener) {
	c.recorder.AddConnectionListener(listener)
}

func (c *Client) RemoveConnectionListener(listener ConnectionListener) {
	c.recorder.RemoveConnectionListener(listener)
}

func (c *Client) login(ctx context.Context, config *internal.Config, setupKey string) error {
	needsLogin := false

	err := cmd.WithBackOff(func() error {
		err := internal.Login(ctx, config, "", "")
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied) {
			log.Println("need login")
			needsLogin = true
			return nil
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("backoff cycle failed: %v", err)
	}

	jwtToken := ""
	if setupKey == "" && needsLogin {
		tokenInfo, err := c.foregroundGetTokenInfo(ctx, config)
		if err != nil {
			return fmt.Errorf("interactive sso login failed: %v", err)
		}
		jwtToken = tokenInfo.AccessToken
	}

	err = cmd.WithBackOff(func() error {
		err := internal.Login(ctx, config, setupKey, jwtToken)
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied) {
			return nil
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("backoff cycle failed: %v", err)
	}

	return nil
}

func (c *Client) foregroundGetTokenInfo(ctx context.Context, config *internal.Config) (*internal.TokenInfo, error) {
	providerConfig, err := internal.GetDeviceAuthorizationFlowInfo(ctx, config)
	if err != nil {
		s, ok := gstatus.FromError(err)
		if ok && s.Code() == codes.NotFound {
			return nil, fmt.Errorf("no SSO provider returned from management. " +
				"If you are using hosting Netbird see documentation at " +
				"https://github.com/netbirdio/netbird/tree/main/management for details")
		} else if ok && s.Code() == codes.Unimplemented {
			return nil, fmt.Errorf("the management server, %s, does not support SSO providers, "+
				"please update your servver or use Setup Keys to login", c.mgmUrl)
		} else {
			return nil, fmt.Errorf("getting device authorization flow info failed with error: %v", err)
		}
	}

	hostedClient := internal.NewHostedDeviceFlow(
		providerConfig.ProviderConfig.Audience,
		providerConfig.ProviderConfig.ClientID,
		providerConfig.ProviderConfig.TokenEndpoint,
		providerConfig.ProviderConfig.DeviceAuthEndpoint,
	)

	flowInfo, err := hostedClient.RequestDeviceCode(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("getting a request device code failed: %v", err)
	}

	go c.urlOpener.Open(flowInfo.VerificationURIComplete)

	waitTimeout := time.Duration(flowInfo.ExpiresIn)
	waitCTX, cancel := context.WithTimeout(context.TODO(), waitTimeout*time.Second)
	defer cancel()

	tokenInfo, err := hostedClient.WaitToken(waitCTX, flowInfo)
	if err != nil {
		return nil, fmt.Errorf("waiting for browser login failed: %v", err)
	}

	return &tokenInfo, nil
}
