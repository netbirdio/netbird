package management

import (
	"context"
	pb "github.com/golang/protobuf/proto" //nolint
	"github.com/golang/protobuf/ptypes/timestamp"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/management/proto"
	"github.com/wiretrustee/wiretrustee/signal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/status"
	"time"
)

// Server an instance of a Management server
type Server struct {
	Store *Store
	wgKey wgtypes.Key
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
		Store: store,
		wgKey: key,
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

	peerKey := req.GetWgPubKey()
	parsedPeerKey, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		log.Warnf("error while parsing peer's Wireguard public key %s on Sync request.", peerKey)
		return status.Errorf(400, "provided wgPubKey %s is invalid", peerKey)
	}

	decrypted, err := signal.Decrypt(req.Body, parsedPeerKey, s.wgKey)
	if err != nil {
		log.Warnf("error while decrypting Sync request message from peer %s", peerKey)
		return status.Errorf(400, "invalid request message")
	}

	syncReq := &proto.SyncRequest{}
	err = pb.Unmarshal(decrypted, syncReq)
	if err != nil {
		log.Warnf("error while umarshalling Sync request message from peer %s", peerKey)
		return status.Errorf(400, "invalid request message")
	}

	peers := s.Store.GetPeersForAPeer(peerKey)

	plainResp := &proto.SyncResponse{
		Peers: peers,
	}

	byteResp, err := pb.Marshal(plainResp)
	if err != nil {
		log.Errorf("failed marshalling SyncResponse %v", err)
		return status.Errorf(500, "error handling request")
	}

	encResp, err := signal.Encrypt(byteResp, parsedPeerKey, s.wgKey)
	if err != nil {
		log.Errorf("failed encrypting SyncResponse %v", err)
		return status.Errorf(500, "error handling request")
	}

	err = srv.Send(&proto.EncryptedMessage{
		WgPubKey: s.wgKey.PublicKey().String(),
		Body:     encResp,
	})

	if err != nil {
		log.Errorf("failed sending SyncResponse %v", err)
		return status.Errorf(500, "error handling request")
	}

	return nil
}

// RegisterPeer adds a peer to the Store. Returns 404 in case the provided setup key doesn't exist
func (s *Server) RegisterPeer(ctx context.Context, req *proto.RegisterPeerRequest) (*proto.RegisterPeerResponse, error) {

	err := s.Store.AddPeer(req.SetupKey, req.Key)
	if err != nil {
		return &proto.RegisterPeerResponse{}, status.Errorf(404, "provided setup key doesn't exists")
	}

	return &proto.RegisterPeerResponse{}, nil
}

// IsHealthy indicates whether the service is healthy
func (s *Server) IsHealthy(ctx context.Context, req *proto.Empty) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}
