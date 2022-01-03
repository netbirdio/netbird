package v2

import (
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/client/internal/v2/event"
	"github.com/wiretrustee/wiretrustee/client/internal/v2/peer"
	mgmProto "github.com/wiretrustee/wiretrustee/management/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// State holds a state of the Engine
// The state update happens in the Engine.handleEvent function
// This state should be synchronized
type State struct {
	peerMap map[string]*peer.Conn
	// STUNs is a list of STUN servers used by ICE
	STUNs []*ice.URL
	// TURNs is a list of STUN servers used by ICE
	TURNs []*ice.URL
}

func (s *State) GetPeer(key string) *peer.Conn {
	return s.peerMap[key]
}

func (engine *Engine) updateSTUNs(stuns []*mgmProto.HostConfig) error {
	if len(stuns) == 0 {
		return nil
	}
	var newSTUNs []*ice.URL
	log.Debugf("got STUNs update from Management Service, updating")
	for _, stun := range stuns {
		url, err := ice.ParseURL(stun.Uri)
		if err != nil {
			return err
		}
		newSTUNs = append(newSTUNs, url)
	}
	engine.state.STUNs = newSTUNs

	return nil
}

func (engine *Engine) updateTURNs(turns []*mgmProto.ProtectedHostConfig) error {
	if len(turns) == 0 {
		return nil
	}
	var newTURNs []*ice.URL
	log.Debugf("got TURNs update from Management Service, updating")
	for _, turn := range turns {
		url, err := ice.ParseURL(turn.HostConfig.Uri)
		if err != nil {
			return err
		}
		url.Username = turn.User
		url.Password = turn.Password
		newTURNs = append(newTURNs, url)
	}
	engine.state.TURNs = newTURNs

	return nil
}

func (engine *Engine) updatePeers(remotePeers []*mgmProto.RemotePeerConfig) error {
	log.Debugf("got peers update from Management Service, total peers to connect to = %d", len(remotePeers))
	remotePeerMap := make(map[string]struct{})
	for _, p := range remotePeers {
		remotePeerMap[p.GetWgPubKey()] = struct{}{}
	}

	//remove peers that are no longer available for us
	toRemove := []string{}
	for p := range engine.state.peerMap {
		if _, ok := remotePeerMap[p]; !ok {
			toRemove = append(toRemove, p)
		}
	}
	err := engine.removePeers(toRemove)
	if err != nil {
		return err
	}

	// add new peers
	for _, p := range remotePeers {
		peerKey := p.GetWgPubKey()
		//peerIPs := p.GetAllowedIps()
		if _, ok := engine.state.peerMap[peerKey]; !ok {
			key, _ := wgtypes.ParseKey(peerKey)
			conn, err := peer.NewConn(peer.ConnConfig{RemoteKey: key.PublicKey().String(), LocalKey: engine.config.WgPrivateKey.PublicKey().String()})
			if err != nil {
				return err
			}
			engine.state.peerMap[peerKey] = conn
			engine.FireEvent(event.New(event.PeerDisconnected, peerKey))
		}

	}
	return nil
}

func (engine *Engine) removePeers(peers []string) error {
	for _, p := range peers {
		err := engine.removePeer(p)
		if err != nil {
			return err
		}
	}
	return nil
}

func (engine *Engine) removeAllPeerConnections() error {
	log.Debugf("removing all peer connections")
	for p := range engine.state.peerMap {
		err := engine.removePeer(p)
		if err != nil {
			return err
		}
	}
	return nil
}

// removePeer closes an existing peer connection and removes a peer
func (engine *Engine) removePeer(peerKey string) error {
	delete(engine.state.peerMap, peerKey)
	p, exists := engine.state.peerMap[peerKey]
	if exists && p != nil {
		delete(engine.state.peerMap, peerKey)
		return p.Close()
	}
	log.Infof("removed peer %s", peerKey)
	return nil
}
