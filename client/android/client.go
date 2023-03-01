package android

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/cmd"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/formatter"
	"github.com/netbirdio/netbird/iface"
)

// ConnectionListener export internal Listener for mobile
type ConnectionListener interface {
	status.Listener
}

// TunAdapter export internal TunAdapter for mobile
type TunAdapter interface {
	iface.TunAdapter
}

type UrlOpener interface {
	Open(string)
}

func init() {
	formatter.SetLogcatFormatter(log.StandardLogger())
}

type Client struct {
	cfgFile       string
	adminURL      string
	mgmUrl        string
	tunAdapter    iface.TunAdapter
	recorder      *status.Status
	ctxCancel     context.CancelFunc
	ctxCancelLock *sync.Mutex
	urlOpener     UrlOpener
	deviceName    string
}

func NewClient(cfgFile, adminURL, mgmURL string, deviceName string, tunAdapter TunAdapter, urlOpener UrlOpener) *Client {
	lvl, _ := log.ParseLevel("trace")
	log.SetLevel(lvl)

	return &Client{
		cfgFile:       cfgFile,
		adminURL:      adminURL,
		mgmUrl:        mgmURL,
		deviceName:    deviceName,
		tunAdapter:    tunAdapter,
		urlOpener:     urlOpener,
		recorder:      status.NewRecorder(),
		ctxCancelLock: &sync.Mutex{},
	}
}

func (c *Client) Run() error {
	cfg, err := internal.UpdateOrCreateConfig(internal.ConfigInput{
		ManagementURL: c.mgmUrl,
		AdminURL:      c.adminURL,
		ConfigPath:    c.cfgFile,
	})

	var ctx context.Context
	ctxWithValues := context.WithValue(context.Background(), system.DeviceNameCtxKey, c.deviceName)
	c.ctxCancelLock.Lock()
	ctx, c.ctxCancel = context.WithCancel(ctxWithValues)
	defer c.ctxCancel()
	c.ctxCancelLock.Unlock()

	log.Debugf("try to login")
	err = c.login(ctx, cfg, "")
	if err != nil {
		return fmt.Errorf("foreground login failed: %v", err)
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

func (c *Client) AddConnectionListener(listener ConnectionListener) {
	c.recorder.AddConnectionListener(listener)
}

func (c *Client) RemoveConnectionListener(listener ConnectionListener) {
	c.recorder.RemoveConnectionListener(listener)
}

func (c *Client) ctxWithCancel(parentCtx context.Context) context.Context {
	c.ctxCancelLock.Lock()
	defer c.ctxCancelLock.Unlock()
	var ctx context.Context
	ctx, c.ctxCancel = context.WithCancel(parentCtx)
	return ctx
}

func (c *Client) login(ctx context.Context, config *internal.Config, setupKey string) error {
	needsLogin := false

	err := c.withBackOff(ctx, func() error {
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

	err = c.withBackOff(ctx, func() error {
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

func (c *Client) withBackOff(ctx context.Context, bf func() error) error {
	return backoff.RetryNotify(
		bf,
		backoff.WithContext(cmd.CLIBackOffSettings, ctx),
		func(err error, duration time.Duration) {
			log.Warnf("retrying Login to the Management service in %v due to error %v", duration, err)
		})
}

func (c *Client) foregroundGetTokenInfo(ctx context.Context, config *internal.Config) (*internal.TokenInfo, error) {
	providerConfig, err := internal.GetDeviceAuthorizationFlowInfo(ctx, config.PrivateKey, config.ManagementURL)
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
	waitCTX, cancel := context.WithTimeout(ctx, waitTimeout*time.Second)
	defer cancel()
	tokenInfo, err := hostedClient.WaitToken(waitCTX, flowInfo)
	if err != nil {
		return nil, fmt.Errorf("waiting for browser login failed: %v", err)
	}

	return &tokenInfo, nil
}
