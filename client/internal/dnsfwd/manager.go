package dnsfwd

import (
	"context"
	"fmt"
	"net"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

const (
	// ListenPort is the port that the DNS forwarder listens on. It has been used by the client peers also
	ListenPort = 5353
	dnsTTL     = 60 //seconds
)

type Manager struct {
	firewall firewall.Manager

	fwRules      []firewall.Rule
	dnsForwarder *DNSForwarder
}

func NewManager(fw firewall.Manager) *Manager {
	return &Manager{
		firewall: fw,
	}
}

func (m *Manager) Start(domains []string) error {
	log.Infof("starting DNS forwarder")
	if m.dnsForwarder != nil {
		return nil
	}

	if err := m.allowDNSFirewall(); err != nil {
		return err
	}

	m.dnsForwarder = NewDNSForwarder(fmt.Sprintf(":%d", ListenPort), dnsTTL)
	go func() {
		if err := m.dnsForwarder.Listen(domains); err != nil {
			// todo handle close error if it is exists
			log.Errorf("failed to start DNS forwarder, err: %v", err)
		}
	}()

	return nil
}

func (m *Manager) UpdateDomains(domains []string) {
	if m.dnsForwarder == nil {
		return
	}

	m.dnsForwarder.UpdateDomains(domains)
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

func (h *Manager) allowDNSFirewall() error {
	dport := &firewall.Port{
		IsRange: false,
		Values:  []int{ListenPort},
	}


	if h.firewall == nil {
		return nil
	}

	dnsRules, err := h.firewall.AddPeerFiltering(net.IP{0, 0, 0, 0}, firewall.ProtocolUDP, nil, dport, firewall.ActionAccept, "", "")
	if err != nil {
		log.Errorf("failed to add allow DNS router rules, err: %v", err)
		return err
	}
	h.fwRules = dnsRules

	return nil
}

func (h *Manager) dropDNSFirewall() error {
	var mErr *multierror.Error
	for _, rule := range h.fwRules {
		if err := h.firewall.DeletePeerRule(rule); err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("failed to delete DNS router rules, err: %v", err))
		}
	}

	h.fwRules = nil
	return nberrors.FormatErrorOrNil(mErr)
}
