package management

import (
	"context"
	"github.com/golang/protobuf/ptypes/timestamp"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/management/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sync"
	"time"
)

// Server an instance of a Management server
type Server struct {
	Store *FileStore
	wgKey wgtypes.Key
	proto.UnimplementedManagementServiceServer
	peerChannels map[string]chan *UpdateChannelMessage
	channelsMux  *sync.Mutex
}

type UpdateChannelMessage struct {
	Update *proto.SyncResponse
}

// NewServer creates a new Management server
func NewServer(dataDir string) (*Server, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	store, err := NewStore(dataDir)
	if err != nil {
		return nil, err
	}
	return &Server{
		Store:        store,
		wgKey:        key,
		peerChannels: make(map[string]chan *UpdateChannelMessage),
		channelsMux:  &sync.Mutex{},
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

func (s *Server) Sync(req *proto.EncryptedMessage, srv proto.ManagementService_SyncServer) error {

	peerKey, err := wgtypes.ParseKey(req.GetWgPubKey())
	if err != nil {
		log.Warnf("error while parsing peer's Wireguard public key %s on Sync request.", peerKey.String())
		return status.Errorf(codes.InvalidArgument, "provided wgPubKey %s is invalid", peerKey.String())
	}

	exists := s.Store.PeerExists(peerKey.String())
	if !exists {
		return status.Errorf(codes.Unauthenticated, "provided peer with the key wgPubKey %s is not registered", peerKey.String())
	}

	syncReq := &proto.SyncRequest{}
	err = DecryptMessage(peerKey, s.wgKey, req, syncReq)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid request message")
	}

	err = s.sendInitialSync(peerKey, srv)
	if err != nil {
		return err
	}

	updates := s.openUpdatesChannel(peerKey.String())
	defer s.closeUpdatesChannel(peerKey.String())

	// keep the peer channel open and send updates when available
	for {
		update := <-updates

		encryptedResp, err := EncryptMessage(peerKey, s.wgKey, update.Update)
		if err != nil {
			return status.Errorf(codes.Internal, "failed processing update message")
		}

		err = srv.SendMsg(encryptedResp)
		if err != nil {
			return status.Errorf(codes.Internal, "failed sending update message")
		}
	}
}

// RegisterPeer adds a peer to the Store. Returns 404 in case the provided setup key doesn't exist
func (s *Server) RegisterPeer(ctx context.Context, req *proto.RegisterPeerRequest) (*proto.RegisterPeerResponse, error) {

	s.channelsMux.Lock()
	defer s.channelsMux.Unlock()

	err := s.Store.AddPeer(req.SetupKey, req.Key)
	if err != nil {
		return &proto.RegisterPeerResponse{}, status.Errorf(codes.NotFound, "provided setup key doesn't exists")
	}

	peers, err := s.Store.GetPeersForAPeer(req.Key)
	if err != nil {
		//todo return a proper error
		return nil, err
	}

	for _, peer := range peers {
		if channel, ok := s.peerChannels[peer]; ok {
			peersToSend := []string{req.Key}
			for _, p := range peers {
				if peer != p {
					peersToSend = append(peersToSend, p)
				}
			}
			update := &proto.SyncResponse{Peers: peersToSend}
			channel <- &UpdateChannelMessage{Update: update}
		}
	}

	return &proto.RegisterPeerResponse{}, nil
}

// IsHealthy indicates whether the service is healthy
func (s *Server) IsHealthy(ctx context.Context, req *proto.Empty) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}

// openUpdatesChannel creates a go channel for a given peer used to deliver updates relevant to the peer.
func (s *Server) openUpdatesChannel(peerKey string) chan *UpdateChannelMessage {
	s.channelsMux.Lock()
	defer s.channelsMux.Unlock()
	channel := make(chan *UpdateChannelMessage, 10)
	//mbragin: todo what if there was a value before?
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
func (s *Server) sendInitialSync(peerKey wgtypes.Key, srv proto.ManagementService_SyncServer) error {

	peers, err := s.Store.GetPeersForAPeer(peerKey.String())
	if err != nil {
		log.Warnf("error getting a list of peers for a peer %s", peerKey.String())
		return err
	}
	plainResp := &proto.SyncResponse{
		Peers: peers,
	}

	encryptedResp, err := EncryptMessage(peerKey, s.wgKey, plainResp)
	if err != nil {
		return status.Errorf(codes.Internal, "error handling request")
	}

	err = srv.Send(encryptedResp)

	if err != nil {
		log.Errorf("failed sending SyncResponse %v", err)
		return status.Errorf(codes.Internal, "error handling request")
	}

	return nil
}
