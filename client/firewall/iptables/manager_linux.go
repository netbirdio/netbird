package iptables

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/iface"
)

// Manager of iptables firewall
type Manager struct {
	mutex sync.Mutex

	wgIface iFaceMapper

	ipv4Client *iptables.IPTables
	aclMgr     *aclManager
	router     *router
}

// iFaceMapper defines subset methods of interface required for manager
type iFaceMapper interface {
	Name() string
	Address() iface.WGAddress
	IsUserspaceBind() bool
}

// Create iptables firewall manager
func Create(context context.Context, wgIface iFaceMapper) (*Manager, error) {
	iptablesClient, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, fmt.Errorf("iptables is not installed in the system or not supported")
	}

	m := &Manager{
		wgIface:    wgIface,
		ipv4Client: iptablesClient,
	}

	m.router, err = newRouterManager(context, iptablesClient, wgIface)
	if err != nil {
		log.Debugf("failed to initialize route related chains: %s", err)
		return nil, err
	}
	m.aclMgr, err = newAclManager(iptablesClient, wgIface, chainRTFWD)
	if err != nil {
		log.Debugf("failed to initialize ACL manager: %s", err)
		return nil, err
	}

	return m, nil
}

// AddPeerFiltering adds a rule to the firewall
//
// Comment will be ignored because some system this feature is not supported
func (m *Manager) AddPeerFiltering(
	ip net.IP,
	protocol firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	direction firewall.RuleDirection,
	action firewall.Action,
	ipsetName string,
	comment string,
) ([]firewall.Rule, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.aclMgr.AddPeerFiltering(ip, protocol, sPort, dPort, direction, action, ipsetName)
}

func (m *Manager) AddRouteFiltering(source netip.Prefix, destination netip.Prefix, proto firewall.Protocol, sPort *firewall.Port, dPort *firewall.Port, direction firewall.RuleDirection, action firewall.Action) (firewall.Rule, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !destination.Addr().Is4() {
		return nil, fmt.Errorf("unsupported IP version: %s", destination.Addr().String())
	}

	return m.router.AddRouteFiltering(source, destination, proto, sPort, dPort, direction, action)
}

// DeletePeerRule from the firewall by rule definition
func (m *Manager) DeletePeerRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.aclMgr.DeletePeerRule(rule)
}

func (m *Manager) DeleteRouteRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.DeleteRouteRule(rule)
}

func (m *Manager) IsServerRouteSupported() bool {
	return true
}

func (m *Manager) AddNatRule(pair firewall.RouterPair) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.AddNatRule(pair)
}

func (m *Manager) RemoveNatRule(pair firewall.RouterPair) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.RemoveNatRule(pair)
}

func (m *Manager) SetLegacyManagement(isLegacy bool) error {
	return firewall.SetLegacyManagement(m.router, isLegacy)
}

// Reset firewall to the default state
func (m *Manager) Reset() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	errAcl := m.aclMgr.Reset()
	if errAcl != nil {
		log.Errorf("failed to clean up ACL rules from firewall: %s", errAcl)
	}
	errMgr := m.router.Reset()
	if errMgr != nil {
		log.Errorf("failed to clean up router rules from firewall: %s", errMgr)
		return errMgr
	}
	return errAcl
}

// AllowNetbird allows netbird interface traffic
func (m *Manager) AllowNetbird() error {
	if !m.wgIface.IsUserspaceBind() {
		return nil
	}

	_, err := m.AddPeerFiltering(
		net.ParseIP("0.0.0.0"),
		"all",
		nil,
		nil,
		firewall.RuleDirectionIN,
		firewall.ActionAccept,
		"",
		"",
	)
	if err != nil {
		return fmt.Errorf("failed to allow netbird interface traffic: %w", err)
	}
	_, err = m.AddPeerFiltering(
		net.ParseIP("0.0.0.0"),
		"all",
		nil,
		nil,
		firewall.RuleDirectionOUT,
		firewall.ActionAccept,
		"",
		"",
	)
	return err
}

// Flush doesn't need to be implemented for this manager
func (m *Manager) Flush() error { return nil }

func getConntrackEstablished() []string {
	return []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
}
