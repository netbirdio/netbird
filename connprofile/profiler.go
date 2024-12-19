package connprofile

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/proto"
)

type Profile struct {
	NetworkMapUpdate    time.Time
	OfferSent           time.Time
	OfferReceived       time.Time
	WireGuardConfigured time.Time
	WireGuardConnected  time.Time
}

type ConnProfiler struct {
	profiles   map[string]*Profile
	profilesMu sync.Mutex
	wgIface    wgIface
	wgMu       sync.Mutex
}

func NewConnProfiler() *ConnProfiler {
	return &ConnProfiler{
		profiles: make(map[string]*Profile),
	}
}

func (p *ConnProfiler) GetProfiles() map[string]Profile {
	p.profilesMu.Lock()
	defer p.profilesMu.Unlock()

	copiedProfiles := make(map[string]Profile)
	for key, profile := range p.profiles {
		copiedProfiles[key] = Profile{
			NetworkMapUpdate:    profile.NetworkMapUpdate,
			OfferSent:           profile.OfferSent,
			OfferReceived:       profile.OfferReceived,
			WireGuardConfigured: profile.WireGuardConfigured,
			WireGuardConnected:  profile.WireGuardConnected,
		}
	}
	return copiedProfiles
}

func (p *ConnProfiler) WGInterfaceUP(wgInterface wgIface) {
	p.wgMu.Lock()
	defer p.wgMu.Unlock()

	if p.wgIface != nil {
		return
	}

	p.wgIface = wgInterface
	go p.watchHandshakes()
}

func (p *ConnProfiler) NetworkMapUpdate(peerConfigs []*proto.RemotePeerConfig) {
	p.profilesMu.Lock()
	defer p.profilesMu.Unlock()

	for _, peerConfig := range peerConfigs {
		profile, ok := p.profiles[peerConfig.WgPubKey]
		if ok {
			continue
		}
		profile = &Profile{
			NetworkMapUpdate: time.Now(),
		}
		p.profiles[peerConfig.WgPubKey] = profile
	}
}

func (p *ConnProfiler) OfferSent(peerID string) {
	p.profilesMu.Lock()
	defer p.profilesMu.Unlock()

	profile, ok := p.profiles[peerID]
	if !ok {
		log.Warnf("OfferSent: profile not found for peer %s", peerID)
		return
	}

	if !profile.OfferSent.IsZero() {
		return
	}
	profile.OfferSent = time.Now()
}

func (p *ConnProfiler) OfferAnswerReceived(peerID string) {
	p.profilesMu.Lock()
	defer p.profilesMu.Unlock()

	profile, ok := p.profiles[peerID]
	if !ok {
		log.Warnf("OfferSent: profile not found for peer %s", peerID)
		return
	}

	if !profile.OfferReceived.IsZero() {
		return
	}
	profile.OfferReceived = time.Now()
}

func (p *ConnProfiler) WireGuardConfigured(peerID string) {
	p.profilesMu.Lock()
	defer p.profilesMu.Unlock()

	profile, ok := p.profiles[peerID]
	if !ok {
		log.Warnf("OfferSent: profile not found for peer %s", peerID)
		return
	}

	if !profile.WireGuardConfigured.IsZero() {
		return
	}
	profile.WireGuardConfigured = time.Now()
}

func (p *ConnProfiler) watchHandshakes() {
	ticker := time.NewTicker(300 * time.Millisecond)
	for {
		select {
		case _ = <-ticker.C:
			p.checkHandshakes()
		}
	}
}

func (p *ConnProfiler) checkHandshakes() {
	stats, err := p.wgIface.GetAllStat()
	if err != nil {
		log.Errorf("watchHandshakes: %v", err)
		return
	}

	p.profilesMu.Lock()
	for peerID, profile := range p.profiles {
		if !profile.WireGuardConnected.IsZero() {
			continue
		}

		stat, ok := stats[peerID]
		if !ok {
			continue
		}

		if stat.LastHandshake.IsZero() {
			continue
		}
		profile.WireGuardConnected = stat.LastHandshake
	}
	p.profilesMu.Unlock()
}
