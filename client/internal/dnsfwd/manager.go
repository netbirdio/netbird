package dnsfwd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/peer"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

const (
	dnsTTL        = 60
	envServerPort = "NB_DNS_FORWARDER_PORT"
)

// ForwarderEntry is a mapping from a domain to a resource ID and a hash of the parent domain list.
type ForwarderEntry struct {
	Domain domain.Domain
	ResID  route.ResID
	Set    firewall.Set
}

type Manager struct {
	firewall       firewall.Manager
	statusRecorder *peer.Status
	localAddr      netip.Addr
	serverPort     uint16

	fwRules      []firewall.Rule
	tcpRules     []firewall.Rule
	dnsForwarder *DNSForwarder
}

func NewManager(fw firewall.Manager, statusRecorder *peer.Status, localAddr netip.Addr) *Manager {
	serverPort := nbdns.ForwarderServerPort
	if envPort := os.Getenv(envServerPort); envPort != "" {
		if port, err := strconv.ParseUint(envPort, 10, 16); err == nil && port > 0 {
			serverPort = uint16(port)
			log.Infof("using custom DNS forwarder port from %s: %d", envServerPort, serverPort)
		} else {
			log.Warnf("invalid %s value %q, using default %d", envServerPort, envPort, nbdns.ForwarderServerPort)
		}
	}

	return &Manager{
		firewall:       fw,
		statusRecorder: statusRecorder,
		localAddr:      localAddr,
		serverPort:     serverPort,
	}
}

func (m *Manager) Start(fwdEntries []*ForwarderEntry) error {
	log.Infof("starting DNS forwarder")
	if m.dnsForwarder != nil {
		return nil
	}

	if err := m.allowDNSFirewall(); err != nil {
		return err
	}

	if m.localAddr.IsValid() && m.firewall != nil {
		if err := m.firewall.AddInboundDNAT(m.localAddr, firewall.ProtocolUDP, nbdns.ForwarderClientPort, m.serverPort); err != nil {
			log.Warnf("failed to add DNS UDP DNAT rule: %v", err)
		} else {
			log.Infof("added DNS UDP DNAT rule: %s:%d -> %s:%d", m.localAddr, nbdns.ForwarderClientPort, m.localAddr, m.serverPort)
		}

		if err := m.firewall.AddInboundDNAT(m.localAddr, firewall.ProtocolTCP, nbdns.ForwarderClientPort, m.serverPort); err != nil {
			log.Warnf("failed to add DNS TCP DNAT rule: %v", err)
		} else {
			log.Infof("added DNS TCP DNAT rule: %s:%d -> %s:%d", m.localAddr, nbdns.ForwarderClientPort, m.localAddr, m.serverPort)
		}
	}

	m.dnsForwarder = NewDNSForwarder(fmt.Sprintf(":%d", m.serverPort), dnsTTL, m.firewall, m.statusRecorder)
	go func() {
		if err := m.dnsForwarder.Listen(fwdEntries); err != nil {
			// todo handle close error if it is exists
			log.Errorf("failed to start DNS forwarder, err: %v", err)
		}
	}()

	return nil
}

func (m *Manager) UpdateDomains(entries []*ForwarderEntry) {
	if m.dnsForwarder == nil {
		return
	}

	m.dnsForwarder.UpdateDomains(entries)
}

func (m *Manager) Stop(ctx context.Context) error {
	if m.dnsForwarder == nil {
		return nil
	}

	var mErr *multierror.Error

	if m.localAddr.IsValid() && m.firewall != nil {
		if err := m.firewall.RemoveInboundDNAT(m.localAddr, firewall.ProtocolUDP, nbdns.ForwarderClientPort, m.serverPort); err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("remove DNS UDP DNAT rule: %w", err))
		}

		if err := m.firewall.RemoveInboundDNAT(m.localAddr, firewall.ProtocolTCP, nbdns.ForwarderClientPort, m.serverPort); err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("remove DNS TCP DNAT rule: %w", err))
		}
	}

	if err := m.dropDNSFirewall(); err != nil {
		mErr = multierror.Append(mErr, err)
	}

	if err := m.dnsForwarder.Close(ctx); err != nil {
		mErr = multierror.Append(mErr, err)
	}

	m.dnsForwarder = nil
	return nberrors.FormatErrorOrNil(mErr)
}

func (m *Manager) allowDNSFirewall() error {
	dport := &firewall.Port{
		IsRange: false,
		Values:  []uint16{m.serverPort},
	}

	if m.firewall == nil {
		return nil
	}

	dnsRules, err := m.firewall.AddPeerFiltering(nil, net.IP{0, 0, 0, 0}, firewall.ProtocolUDP, nil, dport, firewall.ActionAccept, "")
	if err != nil {
		log.Errorf("failed to add allow DNS router rules, err: %v", err)
		return err
	}
	m.fwRules = dnsRules

	tcpRules, err := m.firewall.AddPeerFiltering(nil, net.IP{0, 0, 0, 0}, firewall.ProtocolTCP, nil, dport, firewall.ActionAccept, "")
	if err != nil {
		log.Errorf("failed to add allow DNS router rules, err: %v", err)
		return err
	}
	m.tcpRules = tcpRules

	return nil
}

func (m *Manager) dropDNSFirewall() error {
	var mErr *multierror.Error
	for _, rule := range m.fwRules {
		if err := m.firewall.DeletePeerRule(rule); err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("failed to delete DNS router rules, err: %v", err))
		}
	}
	for _, rule := range m.tcpRules {
		if err := m.firewall.DeletePeerRule(rule); err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("failed to delete DNS router rules, err: %v", err))
		}
	}

	m.fwRules = nil
	m.tcpRules = nil
	return nberrors.FormatErrorOrNil(mErr)
}
