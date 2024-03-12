package iptables

import (
	"context"
	"fmt"
	"net"
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
	router     *routerManager
}

func (m *Manager) ResetV6Firewall() error {
	return nil
}

func (m *Manager) V6Active() bool {
	return false
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

	m.router, err = newRouterManager(context, iptablesClient)
	if err != nil {
		log.Debugf("failed to initialize route related chains: %s", err)
		return nil, err
	}
	m.aclMgr, err = newAclManager(iptablesClient, wgIface, m.router.RouteingFwChainName())
	if err != nil {
		log.Debugf("failed to initialize ACL manager: %s", err)
		return nil, err
	}

	return m, nil
}

// AddFiltering rule to the firewall
//
// Comment will be ignored because some system this feature is not supported
func (m *Manager) AddFiltering(
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

	return m.aclMgr.AddFiltering(ip, protocol, sPort, dPort, direction, action, ipsetName)
}

// DeleteRule from the firewall by rule definition
func (m *Manager) DeleteRule(rule firewall.Rule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.aclMgr.DeleteRule(rule)
}

func (m *Manager) IsServerRouteSupported() bool {
	return true
}

func (m *Manager) InsertRoutingRules(pair firewall.RouterPair) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.InsertRoutingRules(pair)
}

func (m *Manager) RemoveRoutingRules(pair firewall.RouterPair) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.router.RemoveRoutingRules(pair)
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

	_, err := m.AddFiltering(
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
	_, err = m.AddFiltering(
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
