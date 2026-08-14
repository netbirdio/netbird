//go:build linux

// Package vpnplugin implements NetworkManager's VPN plugin D-Bus contract
// (org.freedesktop.NetworkManager.VPN.Plugin) directly over godbus, and
// drives the real netbird daemon's gRPC API to do the actual connect/
// disconnect work.
package vpnplugin

import "github.com/godbus/dbus/v5"

const (
	// PluginInterface is the well-known, toolkit-independent interface every
	// NetworkManager VPN service plugin implements, regardless of its own
	// D-Bus bus name.
	PluginInterface = "org.freedesktop.NetworkManager.VPN.Plugin"

	// PluginObjectPath is the fixed object path every VPN plugin instance
	// exports the interface at; the caller is disambiguated by bus name, not
	// by path.
	PluginObjectPath dbus.ObjectPath = "/org/freedesktop/NetworkManager/VPN/Plugin"

	// ServiceName is the VPN service-type string this plugin registers under
	// in nm-netbird-service.name (vpn.service-type on a matching connection).
	// NetworkManager passes the actual per-instance bus name to claim via
	// --bus-name; it is not necessarily this exact string once multiple
	// simultaneous connections are active.
	ServiceName = "org.freedesktop.NetworkManager.netbird"
)

// serviceState mirrors NetworkManager's NMVpnServiceState enum, used by the
// plugin's StateChanged signal.
type serviceState uint32

const (
	stateUnknown  serviceState = 0
	stateInit     serviceState = 1
	stateShutdown serviceState = 2
	stateStarting serviceState = 3
	stateStarted  serviceState = 4
	stateStopping serviceState = 5
	stateStopped  serviceState = 6
)

// pluginFailure mirrors NetworkManager's NMVpnPluginFailure enum, used by
// the plugin's Failure signal.
type pluginFailure uint32

const (
	failureLoginFailed   pluginFailure = 0
	failureConnectFailed pluginFailure = 1
	failureBadIPConfig   pluginFailure = 2
)

const (
	signalStateChanged    = PluginInterface + ".StateChanged"
	signalSecretsRequired = PluginInterface + ".SecretsRequired"
	signalConfig          = PluginInterface + ".Config"
	signalIP4Config       = PluginInterface + ".Ip4Config"
	signalFailure         = PluginInterface + ".Failure"

	// Well-known keys in the Config/Ip4Config signal payloads, per libnm's
	// nm-vpn-dbus-interface.h.
	configKeyTunDev        = "tundev"
	configKeyHasIP4        = "has-ip4"
	ip4ConfigKeyAddress    = "address"
	ip4ConfigKeyPrefix     = "prefix"
	ip4ConfigKeyNeverDflt  = "never-default"
	ip4ConfigDefaultPrefix = 32

	// configKeyExtGateway is NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY: the host's
	// real external gateway, used by NetworkManager to route to the VPN's
	// own endpoints without looping through the tunnel. It belongs in the
	// Config signal, not Ip4Config, and NetworkManager hard-rejects a
	// Config reply without it.
	configKeyExtGateway = "gateway"
)

// Hint prefixes used in the SecretsRequired signal's "secrets" array, which
// NetworkManager forwards to the auth-dialog helper as repeated --hint
// arguments. Exported so cmd/nm-netbird-auth-dialog can parse them without
// duplicating the convention.
const (
	HintVerificationURIPrefix = "netbird-verification-uri:"
	HintUserCodePrefix        = "netbird-user-code:"
)

// netbird daemon status strings (internal.StatusType's values), duplicated
// here as plain constants to avoid pulling the netbird agent's full internal
// package into this plugin's binary just for four string comparisons.
const (
	netbirdStatusIdle           = "Idle"
	netbirdStatusConnected      = "Connected"
	netbirdStatusLoginFailed    = "LoginFailed"
	netbirdStatusSessionExpired = "SessionExpired"
)
