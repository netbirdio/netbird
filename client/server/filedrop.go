package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/internal/filedrop"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

func (s *Server) fileDropManager() (*filedrop.Manager, error) {
	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		return nil, fmt.Errorf("get active profile: %w", err)
	}
	if !profilemanager.IsValidProfileFilenameStem(activeProf.ID) {
		return nil, fmt.Errorf("invalid profile ID %q", activeProf.ID)
	}

	s.mutex.Lock()
	if s.fileDrop != nil && s.fileDrop.Profile() == activeProf.ID {
		mgr := s.fileDrop
		s.mutex.Unlock()
		return mgr, nil
	}
	old := s.fileDrop
	s.fileDrop = nil
	s.mutex.Unlock()

	if old != nil {
		if err := old.Close(); err != nil {
			log.Warnf("failed to close previous file drop manager: %v", err)
		}
	}

	prefs, err := s.profileManager.ProfilePrefs(activeProf.ID, activeProf.Username)
	if err != nil {
		return nil, fmt.Errorf("resolve profile prefs: %w", err)
	}

	mgr, err := filedrop.NewManager(filedrop.ManagerConfig{
		Profile: activeProf.ID,
		DataDir: filepath.Join(profilemanager.DefaultConfigPathDir, "filedrop", activeProf.ID.String()),
		Store:   filedrop.NewProfileStore(prefs),
		Events:  s.publishFileDropEvent,
	})
	if err != nil {
		return nil, fmt.Errorf("create file drop manager: %w", err)
	}

	seedFileDropDestination(mgr, activeProf.Username)

	s.mutex.Lock()
	if s.fileDrop != nil && s.fileDrop.Profile() == activeProf.ID {
		winner := s.fileDrop
		s.mutex.Unlock()
		_ = mgr.Close()
		return winner, nil
	}
	s.fileDrop = mgr
	s.mutex.Unlock()
	return mgr, nil
}

func (s *Server) publishFileDropEvent(kind filedrop.EventKind, transfer filedrop.Transfer) {
	s.mutex.Lock()
	statusRecorder := s.statusRecorder
	s.mutex.Unlock()
	if statusRecorder == nil {
		return
	}

	var metaKind, userMsg string
	switch kind {
	case filedrop.EventOffer:
		metaKind = proto.MetadataKindFileDropOffer
		userMsg = fmt.Sprintf("%s wants to send you %s", transfer.PeerName, transferLabel(transfer))
	case filedrop.EventCompleted:
		metaKind = proto.MetadataKindFileDropCompleted
		if transfer.Direction == filedrop.DirectionSent {
			userMsg = fmt.Sprintf("Sent %s to %s", transferLabel(transfer), transfer.PeerName)
		} else {
			userMsg = fmt.Sprintf("Received %s from %s", transferLabel(transfer), transfer.PeerName)
		}
	case filedrop.EventFailed:
		metaKind = proto.MetadataKindFileDropFailed
		userMsg = fmt.Sprintf("Transfer of %s failed", transferLabel(transfer))
	case filedrop.EventWithdrawn:
		metaKind = proto.MetadataKindFileDropWithdrawn
	default:
		return
	}

	statusRecorder.PublishEvent(
		proto.SystemEvent_INFO,
		proto.SystemEvent_SYSTEM,
		"file drop transfer update",
		userMsg,
		map[string]string{
			proto.MetadataKindKey:             metaKind,
			proto.MetadataFileDropTransferKey: string(transfer.ID),
			proto.MetadataFileDropPeerKey:     string(transfer.PeerKey),
		},
	)
}

// FileDropSend starts an asynchronous transfer to a peer.
func (s *Server) FileDropSend(ctx context.Context, req *proto.FileDropSendRequest) (*proto.FileDropSendResponse, error) {
	mgr, err := s.fileDropManager()
	if err != nil {
		return nil, err
	}

	s.mutex.Lock()
	statusRecorder := s.statusRecorder
	s.mutex.Unlock()
	if statusRecorder == nil {
		return nil, errors.New("not connected")
	}

	peerState, err := statusRecorder.GetPeer(req.GetPeerKey())
	if err != nil {
		return nil, fmt.Errorf("unknown peer: %w", err)
	}
	addr, err := netip.ParseAddr(peerState.IP)
	if err != nil {
		return nil, fmt.Errorf("parse peer address: %w", err)
	}

	payloads, err := s.buildFileDropPayloads(ctx, req)
	if err != nil {
		return nil, err
	}

	id, err := mgr.Send(filedrop.PeerKey(req.GetPeerKey()), peerState.FQDN, addr.Unmap(), payloads)
	if err != nil {
		return nil, err
	}
	return &proto.FileDropSendResponse{TransferId: string(id)}, nil
}

func (s *Server) buildFileDropPayloads(ctx context.Context, req *proto.FileDropSendRequest) ([]filedrop.Payload, error) {
	var payloads []filedrop.Payload

	if len(req.GetPaths()) > 0 {
		caller, ok := ipcauth.CallerIdentity(ctx)
		if !ok {
			return nil, errors.New("caller identity required to send files")
		}
		for _, path := range req.GetPaths() {
			payload, err := fileDropPayload(caller, path)
			if err != nil {
				return nil, err
			}
			payloads = append(payloads, payload)
		}
	}

	if text := req.GetText(); text != "" {
		if len(text) > filedrop.MaxInlineTextSize {
			return nil, fmt.Errorf("text exceeds %d bytes", filedrop.MaxInlineTextSize)
		}
		payloads = append(payloads, filedrop.TextPayload("text", text))
	}

	if len(payloads) == 0 {
		return nil, errors.New("nothing to send")
	}
	return payloads, nil
}

// FileDropDecide accepts or declines a pending incoming offer.
func (s *Server) FileDropDecide(_ context.Context, req *proto.FileDropDecideRequest) (*proto.FileDropDecideResponse, error) {
	mgr, err := s.fileDropManager()
	if err != nil {
		return nil, err
	}

	id := filedrop.OfferID(req.GetTransferId())
	if req.GetAccept() {
		err = mgr.Accept(id)
	} else {
		err = mgr.Decline(id)
	}
	if err != nil {
		return nil, err
	}
	return &proto.FileDropDecideResponse{}, nil
}

// FileDropCancel aborts a transfer in either direction.
func (s *Server) FileDropCancel(_ context.Context, req *proto.FileDropCancelRequest) (*proto.FileDropCancelResponse, error) {
	mgr, err := s.fileDropManager()
	if err != nil {
		return nil, err
	}
	mgr.Cancel(filedrop.OfferID(req.GetTransferId()))
	return &proto.FileDropCancelResponse{}, nil
}

// FileDropListTransfers returns the transfer history, newest first.
func (s *Server) FileDropListTransfers(context.Context, *proto.FileDropListTransfersRequest) (*proto.FileDropListTransfersResponse, error) {
	mgr, err := s.fileDropManager()
	if err != nil {
		return nil, err
	}

	transfers := mgr.Transfers()
	resp := &proto.FileDropListTransfersResponse{
		Transfers: make([]*proto.FileDropTransfer, 0, len(transfers)),
	}
	for _, t := range transfers {
		resp.Transfers = append(resp.Transfers, fileDropTransferToProto(t))
	}
	return resp, nil
}

// FileDropDeleteTransfer removes one entry from the transfer history.
func (s *Server) FileDropDeleteTransfer(_ context.Context, req *proto.FileDropDeleteTransferRequest) (*proto.FileDropDeleteTransferResponse, error) {
	mgr, err := s.fileDropManager()
	if err != nil {
		return nil, err
	}
	mgr.DeleteTransfer(filedrop.OfferID(req.GetTransferId()))
	return &proto.FileDropDeleteTransferResponse{}, nil
}

// FileDropGetSettings returns the active profile's receiving policy.
func (s *Server) FileDropGetSettings(context.Context, *proto.FileDropGetSettingsRequest) (*proto.FileDropGetSettingsResponse, error) {
	mgr, err := s.fileDropManager()
	if err != nil {
		return nil, err
	}

	policy := mgr.Policy().Get()
	rules := make(map[string]proto.FileDropRule, len(policy.Senders))
	for key, rule := range policy.Senders {
		rules[string(key)] = proto.FileDropRule(rule)
	}

	return &proto.FileDropGetSettingsResponse{
		Mode:           proto.FileDropMode(policy.Mode),
		DestinationDir: mgr.DestinationDir(),
		PeerRules:      rules,
	}, nil
}

// FileDropSetSettings updates the active profile's receiving policy.
func (s *Server) FileDropSetSettings(ctx context.Context, req *proto.FileDropSetSettingsRequest) (*proto.FileDropSetSettingsResponse, error) {
	mgr, err := s.fileDropManager()
	if err != nil {
		return nil, err
	}

	policy := mgr.Policy().Get()
	policy.Mode = filedrop.Mode(req.GetMode())
	if err := mgr.Policy().Set(policy); err != nil {
		return nil, err
	}

	if dir := req.GetDestinationDir(); dir != mgr.DestinationDir() {
		if err := s.validateFileDropDestination(ctx, dir); err != nil {
			return nil, err
		}
		if err := mgr.SetDestinationDir(dir); err != nil {
			return nil, err
		}
	}
	return &proto.FileDropSetSettingsResponse{}, nil
}

func (s *Server) validateFileDropDestination(ctx context.Context, dir string) error {
	if dir == "" {
		return nil
	}
	if !filepath.IsAbs(dir) {
		return errors.New("destination must be an absolute path")
	}

	caller, ok := ipcauth.CallerIdentity(ctx)
	if !ok {
		return errors.New("caller identity required to change the destination")
	}

	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	if !info.IsDir() {
		return errors.New("destination is not a directory")
	}
	return checkDirOwnership(caller, dir, info)
}

// FileDropSetPeerRule sets or clears a per-sender exception.
func (s *Server) FileDropSetPeerRule(_ context.Context, req *proto.FileDropSetPeerRuleRequest) (*proto.FileDropSetPeerRuleResponse, error) {
	mgr, err := s.fileDropManager()
	if err != nil {
		return nil, err
	}
	if err := mgr.SetSenderRule(filedrop.PeerKey(req.GetPeerKey()), filedrop.SenderRule(req.GetRule())); err != nil {
		return nil, err
	}
	return &proto.FileDropSetPeerRuleResponse{}, nil
}

func fileDropTransferToProto(t filedrop.Transfer) *proto.FileDropTransfer {
	files := make([]*proto.FileDropFile, 0, len(t.Files))
	for _, f := range t.Files {
		files = append(files, &proto.FileDropFile{
			Name:        f.Name,
			Size:        f.Size,
			ContentType: f.ContentType,
			IsText:      f.Kind == filedrop.KindText,
			Text:        f.Text,
		})
	}

	return &proto.FileDropTransfer{
		Id:             string(t.ID),
		Outgoing:       t.Direction == filedrop.DirectionSent,
		PeerKey:        string(t.PeerKey),
		PeerName:       t.PeerName,
		Files:          files,
		State:          proto.FileDropState(t.State),
		Transferred:    t.Transferred,
		TotalSize:      t.TotalSize,
		CreatedAt:      timestamppb.New(t.CreatedAt),
		UpdatedAt:      timestamppb.New(t.UpdatedAt),
		DeliveredPaths: t.DeliveredPaths,
		Error:          t.Error,
		Reason:         proto.FileDropReason(t.Reason),
	}
}

func transferLabel(t filedrop.Transfer) string {
	if len(t.Files) == 1 {
		return t.Files[0].Name
	}
	return fmt.Sprintf("%d files", len(t.Files))
}

func fileDropPayload(caller ipcauth.Identity, path string) (filedrop.Payload, error) {
	f, err := ipcauth.OpenOwnedFile(caller, path)
	if err != nil {
		return filedrop.Payload{}, fmt.Errorf("open %s: %w", path, err)
	}
	info, err := f.Stat()
	closeErr := f.Close()
	if err != nil {
		return filedrop.Payload{}, fmt.Errorf("stat %s: %w", path, err)
	}
	if closeErr != nil {
		return filedrop.Payload{}, fmt.Errorf("close %s: %w", path, closeErr)
	}

	return filedrop.Payload{
		Meta: filedrop.FileMeta{
			Name:        filepath.Base(path),
			Size:        info.Size(),
			ContentType: mime.TypeByExtension(filepath.Ext(path)),
		},
		Open: func(offset int64) (io.ReadCloser, error) {
			f, err := ipcauth.OpenOwnedFile(caller, path)
			if err != nil {
				return nil, err
			}
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				_ = f.Close()
				return nil, err
			}
			return f, nil
		},
	}, nil
}

// seedFileDropDestination gives a profile a delivery directory on first use, so
// a received file always has somewhere to land. Resolved from the profile's own
// user rather than the process: the daemon runs as root, whose home is not where
// the user would look for their downloads.
func seedFileDropDestination(mgr *filedrop.Manager, username string) {
	if mgr.DestinationDir() != "" {
		return
	}

	u, err := user.Lookup(username)
	if err != nil {
		log.Warnf("cannot resolve home of %s for the file drop destination: %v", username, err)
		return
	}
	if u.HomeDir == "" {
		log.Warnf("user %s has no home directory for the file drop destination", username)
		return
	}

	dir := filepath.Join(u.HomeDir, "Downloads", "NetBird")
	if err := mgr.SetDestinationDir(dir); err != nil {
		log.Warnf("failed to set the default file drop destination: %v", err)
	}
}
