package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/encryption"
	"github.com/wiretrustee/wiretrustee/management/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server an instance of a Management server
type Server struct {
	accountManager *AccountManager
	wgKey          wgtypes.Key
	proto.UnimplementedManagementServiceServer
	peerChannels map[string]chan *UpdateChannelMessage
	channelsMux  *sync.Mutex
	config       *Config
}

// AllowedIPsFormat generates Wireguard AllowedIPs format (e.g. 100.30.30.1/32)
const AllowedIPsFormat = "%s/32"

type UpdateChannelMessage struct {
	Update *proto.SyncResponse
}

// NewServer creates a new Management server
func NewServer(config *Config) (*Server, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	store, err := NewStore(config.Datadir)
	if err != nil {
		return nil, err
	}
	return &Server{
		wgKey: key,
		// peerKey -> event channel
		peerChannels:   make(map[string]chan *UpdateChannelMessage),
		channelsMux:    &sync.Mutex{},
		accountManager: NewManager(store),
		config:         config,
	}, nil
}

func (s *Server) GetServerKey(ctx context.Context, req *proto.Empty) (*proto.ServerKeyResponse, error) {

	// todo introduce something more meaningful with the key expiration/rotation
	now := time.Now().Add(24 * time.Hour)
	secs := int64(now.Second())
	nanos := int32(now.Nanosecond())
	expiresAt := &timestamp.Timestamp{Seconds: secs, Nanos: nanos}

	return &proto.ServerKeyResponse{
		Key:       s.wgKey.PublicKey().String(),
		ExpiresAt: expiresAt,
	}, nil
}

//Sync validates the existence of a connecting peer, sends an initial state (all available for the connecting peers) and
// notifies the connected peer of any updates (e.g. new peers under the same account)
func (s *Server) Sync(req *proto.EncryptedMessage, srv proto.ManagementService_SyncServer) error {

	log.Debugf("Sync request from peer %s", req.WgPubKey)

	peerKey, err := wgtypes.ParseKey(req.GetWgPubKey())
	if err != nil {
		log.Warnf("error while parsing peer's Wireguard public key %s on Sync request.", peerKey.String())
		return status.Errorf(codes.InvalidArgument, "provided wgPubKey %s is invalid", peerKey.String())
	}

	peer, err := s.accountManager.GetPeer(peerKey.String())
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "provided peer with the key wgPubKey %s is not registered", peerKey.String())
	}

	syncReq := &proto.SyncRequest{}
	err = encryption.DecryptMessage(peerKey, s.wgKey, req.Body, syncReq)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid request message")
	}

	err = s.sendInitialSync(peerKey, peer, srv)
	if err != nil {
		return err
	}

	updates := s.openUpdatesChannel(peerKey.String())

	// keep a connection to the peer and send updates when available
	for {
		select {
		// condition when there are some updates
		case update, open := <-updates:
			if !open {
				// updates channel has been closed
				return nil
			}
			log.Debugf("recevied an update for peer %s", peerKey.String())

			encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, update.Update)
			if err != nil {
				return status.Errorf(codes.Internal, "failed processing update message")
			}

			err = srv.SendMsg(&proto.EncryptedMessage{
				WgPubKey: s.wgKey.PublicKey().String(),
				Body:     encryptedResp,
			})
			if err != nil {
				return status.Errorf(codes.Internal, "failed sending update message")
			}
		// condition when client <-> server connection has been terminated
		case <-srv.Context().Done():
			// happens when connection drops, e.g. client disconnects
			log.Debugf("stream of peer %s has been closed", peerKey.String())
			s.closeUpdatesChannel(peerKey.String())
			return srv.Context().Err()
		}
	}
}

// RegisterPeer adds a peer to the Store. Returns 404 in case the provided setup key doesn't exist
func (s *Server) RegisterPeer(ctx context.Context, req *proto.RegisterPeerRequest) (*proto.RegisterPeerResponse, error) {

	log.Debugf("RegisterPeer request from peer %s", req.Key)

	s.channelsMux.Lock()
	defer s.channelsMux.Unlock()

	peer, err := s.accountManager.AddPeer(req.SetupKey, req.Key)
	if err != nil {
		return &proto.RegisterPeerResponse{}, status.Errorf(codes.NotFound, "provided setup key doesn't exists")
	}

	peers, err := s.accountManager.GetPeersForAPeer(peer.Key)
	if err != nil {
		//todo return a proper error
		return nil, err
	}

	// notify other peers of our registration
	for _, remotePeer := range peers {
		if channel, ok := s.peerChannels[remotePeer.Key]; ok {
			// exclude notified peer and add ourselves
			peersToSend := []*Peer{peer}
			for _, p := range peers {
				if remotePeer.Key != p.Key {
					peersToSend = append(peersToSend, p)
				}
			}
			update := s.toSyncResponse(peer, peersToSend)
			channel <- &UpdateChannelMessage{Update: update}
		}
	}

	return &proto.RegisterPeerResponse{}, nil
}

func toResponseProto(configProto ConfigProto) proto.HostConfig_Protocol {
	switch configProto {
	case UDP:
		return proto.HostConfig_UDP
	case UDPWithTLS:
		return proto.HostConfig_UDP_WITH_TLS
	case TCP:
		return proto.HostConfig_TCP
	case TCPWithTLS:
		return proto.HostConfig_UDP_WITH_TLS
	default:
		//mbragin: todo something better?
		panic(fmt.Errorf("unexpected config protocol type %v", configProto))
	}
}

func (s *Server) toSyncResponse(peer *Peer, peers []*Peer) *proto.SyncResponse {

	var stuns []*proto.HostConfig
	for _, stun := range s.config.Stuns {
		stuns = append(stuns, &proto.HostConfig{
			Host:     stun.Host,
			Port:     stun.Port,
			Protocol: toResponseProto(stun.Proto),
		})
	}
	var turns []*proto.ProtectedHostConfig
	for _, turn := range s.config.Turns {
		turns = append(turns, &proto.ProtectedHostConfig{
			HostConfig: &proto.HostConfig{
				Host:     turn.Host,
				Port:     turn.Port,
				Protocol: toResponseProto(turn.Proto),
			},
			User:     turn.Username,
			Password: string(turn.Password),
		})
	}

	//todo move to config
	wtConfig := &proto.WiretrusteeConfig{
		Stuns: stuns,
		Turns: turns,
		Signal: &proto.HostConfig{
			Host:     s.config.Signal.Host,
			Port:     s.config.Signal.Port,
			Protocol: toResponseProto(s.config.Signal.Proto),
		},
	}

	pConfig := &proto.PeerConfig{
		Address: peer.IP.String(),
	}

	remotePeers := make([]*proto.RemotePeerConfig, 0, len(peers))
	for _, rPeer := range peers {
		remotePeers = append(remotePeers, &proto.RemotePeerConfig{
			WgPubKey:   rPeer.Key,
			AllowedIps: []string{fmt.Sprintf(AllowedIPsFormat, rPeer.IP)}, //todo /32
		})
	}

	return &proto.SyncResponse{
		WiretrusteeConfig: wtConfig,
		PeerConfig:        pConfig,
		RemotePeers:       remotePeers,
	}
}

// IsHealthy indicates whether the service is healthy
func (s *Server) IsHealthy(ctx context.Context, req *proto.Empty) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}

// openUpdatesChannel creates a go channel for a given peer used to deliver updates relevant to the peer.
func (s *Server) openUpdatesChannel(peerKey string) chan *UpdateChannelMessage {
	s.channelsMux.Lock()
	defer s.channelsMux.Unlock()
	if channel, ok := s.peerChannels[peerKey]; ok {
		delete(s.peerChannels, peerKey)
		close(channel)
	}
	//mbragin: todo shouldn't it be more? or configurable?
	channel := make(chan *UpdateChannelMessage, 100)
	s.peerChannels[peerKey] = channel

	log.Debugf("opened updates channel for a peer %s", peerKey)
	return channel
}

// closeUpdatesChannel closes updates channel of a given peer
func (s *Server) closeUpdatesChannel(peerKey string) {
	s.channelsMux.Lock()
	defer s.channelsMux.Unlock()
	if channel, ok := s.peerChannels[peerKey]; ok {
		delete(s.peerChannels, peerKey)
		close(channel)
	}

	log.Debugf("closed updates channel of a peer %s", peerKey)
}

// sendInitialSync sends initial proto.SyncResponse to the peer requesting synchronization
func (s *Server) sendInitialSync(peerKey wgtypes.Key, peer *Peer, srv proto.ManagementService_SyncServer) error {

	peers, err := s.accountManager.GetPeersForAPeer(peer.Key)
	if err != nil {
		log.Warnf("error getting a list of peers for a peer %s", peer.Key)
		return err
	}
	plainResp := s.toSyncResponse(peer, peers)

	encryptedResp, err := encryption.EncryptMessage(peerKey, s.wgKey, plainResp)
	if err != nil {
		return status.Errorf(codes.Internal, "error handling request")
	}

	err = srv.Send(&proto.EncryptedMessage{
		WgPubKey: s.wgKey.PublicKey().String(),
		Body:     encryptedResp,
	})

	if err != nil {
		log.Errorf("failed sending SyncResponse %v", err)
		return status.Errorf(codes.Internal, "error handling request")
	}

	return nil
}
