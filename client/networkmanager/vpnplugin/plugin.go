//go:build linux

package vpnplugin

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"

	nbproto "github.com/netbirdio/netbird/client/proto"
)

// Plugin implements org.freedesktop.NetworkManager.VPN.Plugin over godbus,
// driving the netbird daemon's gRPC API to connect and disconnect.
type Plugin struct {
	conn    *dbus.Conn
	persist bool

	mu     sync.Mutex
	cancel context.CancelFunc
	daemon *daemonClient
	ssoAck chan struct{}

	quitOnce sync.Once
	quit     chan struct{}
}

// New builds a Plugin bound to an already-connected system bus connection.
// persist controls whether the process should keep running after
// Disconnect, mirroring nm-openvpn-service's --persist flag.
func New(conn *dbus.Conn, persist bool) *Plugin {
	return &Plugin{conn: conn, persist: persist, quit: make(chan struct{})}
}

// Export publishes the plugin object at PluginObjectPath on the bus
// connection it was created with.
func (p *Plugin) Export() error {
	return p.conn.Export(p, PluginObjectPath, PluginInterface)
}

// Quit is closed when the plugin decides the process should exit: after a
// successful Disconnect, unless persist was requested.
func (p *Plugin) Quit() <-chan struct{} {
	return p.quit
}

// Connect is called by NetworkManager to bring the VPN connection up.
func (p *Plugin) Connect(connection map[string]map[string]dbus.Variant) *dbus.Error {
	return p.connect(connection)
}

// ConnectInteractive is Connect's variant for interactive activations; this
// plugin does not vary its behavior based on the extra "details" argument.
func (p *Plugin) ConnectInteractive(connection map[string]map[string]dbus.Variant, _ map[string]dbus.Variant) *dbus.Error {
	return p.connect(connection)
}

// NeedSecrets always reports that no secrets are required upfront: SSO
// login, when needed, is requested dynamically mid-Connect via the
// SecretsRequired signal instead.
func (p *Plugin) NeedSecrets(_ map[string]map[string]dbus.Variant) (string, *dbus.Error) {
	return "", nil
}

// NewSecrets is called once the auth-dialog helper has acknowledged an SSO
// prompt raised via SecretsRequired, unblocking the waiting connect
// goroutine.
func (p *Plugin) NewSecrets(_ map[string]map[string]dbus.Variant) *dbus.Error {
	p.mu.Lock()
	ack := p.ssoAck
	p.ssoAck = nil
	p.mu.Unlock()

	if ack != nil {
		close(ack)
	}
	return nil
}

// Disconnect tears down the active connection attempt, if any, and brings
// the netbird daemon down while leaving it logged in.
func (p *Plugin) Disconnect() *dbus.Error {
	p.mu.Lock()
	cancel := p.cancel
	daemon := p.daemon
	p.cancel = nil
	p.daemon = nil
	p.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	p.emitStateChanged(stateStopping)

	go func() {
		if daemon != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := daemon.down(ctx); err != nil {
				log.Warnf("netbird down: %v", err)
			}
			cancel()
			if err := daemon.Close(); err != nil {
				log.Debugf("close netbird daemon connection: %v", err)
			}
		}
		p.stop()
	}()

	return nil
}

func (p *Plugin) connect(connection map[string]map[string]dbus.Variant) *dbus.Error {
	data, secrets := extractVPNStrings(connection)
	cfg, err := parseSettings(data, secrets)
	if err != nil {
		return dbus.MakeFailedError(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	p.mu.Lock()
	oldCancel, oldDaemon := p.cancel, p.daemon
	p.cancel, p.daemon = cancel, nil
	p.mu.Unlock()

	if oldCancel != nil {
		oldCancel()
	}
	if oldDaemon != nil {
		if err := oldDaemon.Close(); err != nil {
			log.Debugf("close previous netbird daemon connection: %v", err)
		}
	}

	go p.runConnect(ctx, cfg)
	return nil
}

func (p *Plugin) runConnect(ctx context.Context, cfg *settings) {
	p.emitStateChanged(stateStarting)

	daemon, err := dialDaemon(ctx)
	if err != nil {
		p.fail(failureConnectFailed, err)
		return
	}
	p.mu.Lock()
	p.daemon = daemon
	p.mu.Unlock()

	if err := daemon.setConfig(ctx, cfg.setConfigRequest()); err != nil {
		log.Debugf("netbird SetConfig: %v", err)
	}

	loginResp, err := daemon.login(ctx, cfg.loginRequest())
	if err != nil {
		p.fail(failureLoginFailed, fmt.Errorf("login: %w", err))
		return
	}

	if loginResp.NeedsSSOLogin {
		if err := p.waitForSSO(ctx, daemon, loginResp); err != nil {
			p.fail(failureLoginFailed, fmt.Errorf("SSO login: %w", err))
			return
		}
	}

	if err := daemon.up(ctx); err != nil {
		p.fail(failureConnectFailed, fmt.Errorf("up: %w", err))
		return
	}

	p.watchStatus(ctx, daemon, cfg)
}

// waitForSSO emits SecretsRequired with the SSO verification URL and blocks
// until nm-netbird-auth-dialog acknowledges it via NewSecrets, then waits
// for the actual login to complete. The ack only means the browser was
// opened, not that login succeeded: NetworkManager's own secrets-request
// has a hard timeout (observed around 25-40s) far shorter than a real
// human SSO flow can take, so the auth-dialog must answer quickly and this
// long wait has to happen here instead, in a process NM isn't timing.
func (p *Plugin) waitForSSO(ctx context.Context, daemon *daemonClient, resp *nbproto.LoginResponse) error {
	ack := make(chan struct{})
	p.mu.Lock()
	p.ssoAck = ack
	p.mu.Unlock()

	message := fmt.Sprintf("Open the following link in your browser to sign in to NetBird:\n%s", resp.VerificationURIComplete)
	hints := []string{
		HintVerificationURIPrefix + resp.VerificationURIComplete,
		HintUserCodePrefix + resp.UserCode,
	}
	if err := p.conn.Emit(PluginObjectPath, signalSecretsRequired, message, hints); err != nil {
		return fmt.Errorf("emit SecretsRequired: %w", err)
	}

	select {
	case <-ack:
	case <-ctx.Done():
		return ctx.Err()
	}

	return daemon.waitSSOLogin(ctx, resp.UserCode)
}

func (p *Plugin) watchStatus(ctx context.Context, daemon *daemonClient, cfg *settings) {
	stream, err := daemon.subscribeStatus(ctx)
	if err != nil {
		p.fail(failureConnectFailed, fmt.Errorf("subscribe status: %w", err))
		return
	}

	activated := false
	for {
		resp, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			p.fail(failureConnectFailed, fmt.Errorf("status stream: %w", err))
			return
		}

		switch resp.Status {
		case netbirdStatusConnected:
			if !activated {
				p.reportConnected(ctx, daemon, cfg, resp)
				activated = true
			}
		case netbirdStatusIdle:
			if activated {
				// The daemon went idle on its own (e.g. `netbird down` run
				// directly, bypassing NetworkManager entirely): stop like
				// Disconnect would, so NetworkManager's own active-connection
				// state doesn't go stale believing we're still connected.
				p.stop()
				return
			}
		case netbirdStatusLoginFailed, netbirdStatusSessionExpired:
			p.fail(failureLoginFailed, fmt.Errorf("netbird status: %s", resp.Status))
			return
		}
	}
}

func (p *Plugin) reportConnected(ctx context.Context, daemon *daemonClient, cfg *settings, resp *nbproto.StatusResponse) {
	tundev := cfg.interfaceName
	if tundev == "" {
		if gcfg, err := daemon.getConfig(ctx); err != nil {
			log.Debugf("GetConfig: %v", err)
		} else {
			tundev = gcfg.InterfaceName
		}
	}

	// Config must be emitted before Ip4Config: NetworkManager treats an
	// Ip4Config that arrives before any Config as a legacy combined
	// message and demands the (config-level) gateway key inside it
	// instead, failing this same "no VPN gateway address received" check
	// a different way.
	configValues := map[string]dbus.Variant{
		configKeyTunDev: dbus.MakeVariant(tundev),
		configKeyHasIP4: dbus.MakeVariant(true),
	}
	// NetworkManager hard-rejects a Config reply without this: it is the
	// host's real external gateway, not anything netbird-specific, used to
	// route to the VPN's own endpoints without looping through the tunnel.
	if gw, ok := defaultIPv4Gateway(); ok {
		configValues[configKeyExtGateway] = dbus.MakeVariant(gw)
	} else {
		log.Warnf("could not determine the host's default IPv4 gateway; NetworkManager will likely reject this connection")
	}

	if err := p.conn.Emit(PluginObjectPath, signalConfig, configValues); err != nil {
		log.Debugf("emit Config signal: %v", err)
	}

	if addr, prefix, ok := localPeerAddress(resp); ok {
		if err := p.conn.Emit(PluginObjectPath, signalIP4Config, map[string]dbus.Variant{
			ip4ConfigKeyAddress:   dbus.MakeVariant(addr),
			ip4ConfigKeyPrefix:    dbus.MakeVariant(uint32(prefix)),
			ip4ConfigKeyNeverDflt: dbus.MakeVariant(true),
		}); err != nil {
			log.Debugf("emit Ip4Config signal: %v", err)
		}
	}

	p.emitStateChanged(stateStarted)
}

func (p *Plugin) fail(reason pluginFailure, err error) {
	log.Warnf("netbird VPN plugin: %v", err)
	if emitErr := p.conn.Emit(PluginObjectPath, signalFailure, uint32(reason)); emitErr != nil {
		log.Debugf("emit Failure signal: %v", emitErr)
	}
	p.stop()
}

func (p *Plugin) emitStateChanged(state serviceState) {
	if err := p.conn.Emit(PluginObjectPath, signalStateChanged, uint32(state)); err != nil {
		log.Debugf("emit StateChanged signal: %v", err)
	}
}

// stop reports the terminal stopped state and, unless persist was
// requested, lets the process exit. Every path that ends the connection
// without going through NetworkManager's own Disconnect call (an external
// `netbird down`, a login failure, a lost status stream) must still reach
// this, or NetworkManager's active-connection state goes stale believing
// the tunnel is still up.
func (p *Plugin) stop() {
	p.emitStateChanged(stateStopped)
	if !p.persist {
		p.quitOnce.Do(func() { close(p.quit) })
	}
}

func extractVPNStrings(connection map[string]map[string]dbus.Variant) (data, secrets map[string]string) {
	vpn := connection["vpn"]
	data, _ = vpn["data"].Value().(map[string]string)
	secrets, _ = vpn["secrets"].Value().(map[string]string)
	return data, secrets
}

// localPeerAddress extracts the local peer's overlay IPv4 address from a
// status snapshot, returning it in the network-byte-order form NetworkManager's
// VPN plugin D-Bus API documents for Ip4Config's "address" key, along with
// its prefix length.
func localPeerAddress(resp *nbproto.StatusResponse) (uint32, int, bool) {
	if resp.FullStatus == nil || resp.FullStatus.LocalPeerState == nil {
		return 0, 0, false
	}

	raw := resp.FullStatus.LocalPeerState.IP
	if raw == "" {
		return 0, 0, false
	}

	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		addr, addrErr := netip.ParseAddr(raw)
		if addrErr != nil {
			return 0, 0, false
		}
		prefix = netip.PrefixFrom(addr, ip4ConfigDefaultPrefix)
	}
	if !prefix.Addr().Is4() {
		return 0, 0, false
	}

	b := prefix.Addr().As4()
	return binary.BigEndian.Uint32(b[:]), prefix.Bits(), true
}
