package dnsfwd

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

const (
	ListenPort = 5353
)

type Manager struct {
	Firewall firewall.Manager

	dnsRules []firewall.Rule
	service  *DNSForwarder
}

func (m *Manager) Start() error {
	log.Infof("starting DNS forwarder")
	if m.service != nil {
		return nil
	}

	if err := m.allowDNSFirewall(); err != nil {
		return err
	}

	m.service = &DNSForwarder{
		// todo listen only NetBird interface
		ListenAddress: fmt.Sprintf(":%d", ListenPort),
		TTL:           300,
	}

	go func() {
		if err := m.service.Listen(); err != nil {
			// todo handle close error if it is exists
			log.Errorf("failed to start DNS forwarder, err: %v", err)
		}
	}()

	return nil
}

func (m *Manager) Stop(ctx context.Context) error {
	if m.service == nil {
		return nil
	}

	err := m.service.Close(ctx)
	m.service = nil
	return err
}

func (h *Manager) allowDNSFirewall() error {
	dport := &firewall.Port{
		IsRange: false,
		Values:  []int{ListenPort},
	}
	dnsRules, err := h.Firewall.AddPeerFiltering(net.ParseIP("0.0.0.0"), firewall.ProtocolUDP, nil, dport, firewall.RuleDirectionIN, firewall.ActionAccept, "", "")
	if err != nil {
		log.Errorf("failed to add allow DNS router rules, err: %v", err)
		return err
	}
	h.dnsRules = dnsRules

	return nil
}

func (h *Manager) dropDNSFirewall() error {
	if len(h.dnsRules) == 0 {
		return nil
	}

	for _, rule := range h.dnsRules {
		if err := h.Firewall.DeletePeerRule(rule); err != nil {
			log.Errorf("failed to delete DNS router rules, err: %v", err)
			return err
		}
	}

	h.dnsRules = nil
	return nil
}
