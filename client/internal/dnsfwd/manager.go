package dnsfwd

import (
	"context"
	"fmt"
	"net"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/route"
)

const (
	// ListenPort is the port that the DNS forwarder listens on. It has been used by the client peers also
	ListenPort = 5353
	dnsTTL     = 60 //seconds
)

// ForwarderEntry is a mapping from a domain to a resource ID and a hash of the parent domain list.
type ForwarderEntry struct {
	Domain     domain.Domain
	ResId      route.ID
	DomainHash firewall.Set
}

type Manager struct {
	firewall       firewall.Manager
	statusRecorder *peer.Status

	fwRules      []firewall.Rule
	dnsForwarder *DNSForwarder
}

func NewManager(fw firewall.Manager, statusRecorder *peer.Status) *Manager {
	return &Manager{
		firewall:       fw,
		statusRecorder: statusRecorder,
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

	m.dnsForwarder = NewDNSForwarder(fmt.Sprintf(":%d", ListenPort), dnsTTL, m.firewall, m.statusRecorder)
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
		Values:  []uint16{ListenPort},
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

	return nil
}

func (m *Manager) dropDNSFirewall() error {
	var mErr *multierror.Error
	for _, rule := range m.fwRules {
		if err := m.firewall.DeletePeerRule(rule); err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("failed to delete DNS router rules, err: %v", err))
		}
	}

	m.fwRules = nil
	return nberrors.FormatErrorOrNil(mErr)
}
