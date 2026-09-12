//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"errors"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/netbirdio/netbird/client/proto"
)

// EventFilesDropped carries the absolute paths of files natively dropped on the
// main window.
const EventFilesDropped = "netbird:files:dropped"

// FileDropFile mirrors one payload item of a transfer.
type FileDropFile struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	ContentType string `json:"contentType"`
	IsText      bool   `json:"isText"`
	Text        string `json:"text"`
}

// FileDropTransfer mirrors proto.FileDropTransfer for the frontend.
type FileDropTransfer struct {
	ID             string         `json:"id"`
	Outgoing       bool           `json:"outgoing"`
	PeerKey        string         `json:"peerKey"`
	PeerName       string         `json:"peerName"`
	Files          []FileDropFile `json:"files"`
	State          int32          `json:"state"`
	Transferred    int64          `json:"transferred"`
	TotalSize      int64          `json:"totalSize"`
	CreatedAt      time.Time      `json:"createdAt"`
	UpdatedAt      time.Time      `json:"updatedAt"`
	DeliveredPaths []string       `json:"deliveredPaths"`
	Error          string         `json:"error"`
	Reason         int32          `json:"reason"`
}

// FileDropSettings mirrors the daemon's receiving policy with ordinal enums.
type FileDropSettings struct {
	Mode           int32            `json:"mode"`
	DestinationDir string           `json:"destinationDir"`
	PeerRules      map[string]int32 `json:"peerRules"`
}

// FileDrop bridges the daemon's file transfer RPCs to the frontend.
type FileDrop struct {
	conn DaemonConn
}

func NewFileDrop(conn DaemonConn) *FileDrop {
	return &FileDrop{conn: conn}
}

// List returns the transfer history, newest first.
func (s *FileDrop) List(ctx context.Context) ([]FileDropTransfer, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return nil, err
	}
	resp, err := cli.FileDropListTransfers(ctx, &proto.FileDropListTransfersRequest{})
	if err != nil {
		return nil, err
	}

	out := make([]FileDropTransfer, 0, len(resp.GetTransfers()))
	for _, t := range resp.GetTransfers() {
		out = append(out, fileDropTransferFromProto(t))
	}
	return out, nil
}

// Send starts a transfer of local files and/or an inline text to a peer.
func (s *FileDrop) Send(ctx context.Context, peerKey string, paths []string, text string) (string, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return "", err
	}
	resp, err := cli.FileDropSend(ctx, &proto.FileDropSendRequest{
		PeerKey: peerKey,
		Paths:   paths,
		Text:    text,
	})
	if err != nil {
		return "", err
	}
	return resp.GetTransferId(), nil
}

// PickFiles opens the native file picker; an empty result means cancelled.
func (s *FileDrop) PickFiles(_ context.Context) ([]string, error) {
	return application.Get().Dialog.OpenFile().PromptForMultipleSelection()
}

// PickDirectory opens the native directory picker; empty means cancelled.
func (s *FileDrop) PickDirectory(_ context.Context) (string, error) {
	return application.Get().Dialog.OpenFile().
		CanChooseDirectories(true).
		CanChooseFiles(false).
		PromptForSingleSelection()
}

// Decide accepts or declines a pending incoming offer.
func (s *FileDrop) Decide(ctx context.Context, id string, accept bool) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.FileDropDecide(ctx, &proto.FileDropDecideRequest{TransferId: id, Accept: accept})
	return err
}

// Cancel aborts a transfer.
func (s *FileDrop) Cancel(ctx context.Context, id string) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.FileDropCancel(ctx, &proto.FileDropCancelRequest{TransferId: id})
	return err
}

// Delete removes a history entry.
func (s *FileDrop) Delete(ctx context.Context, id string) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.FileDropDeleteTransfer(ctx, &proto.FileDropDeleteTransferRequest{TransferId: id})
	return err
}

// GetSettings returns the receiving policy of the active profile.
func (s *FileDrop) GetSettings(ctx context.Context) (FileDropSettings, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return FileDropSettings{}, err
	}
	resp, err := cli.FileDropGetSettings(ctx, &proto.FileDropGetSettingsRequest{})
	if err != nil {
		return FileDropSettings{}, err
	}

	rules := make(map[string]int32, len(resp.GetPeerRules()))
	for key, rule := range resp.GetPeerRules() {
		rules[key] = int32(rule)
	}
	return FileDropSettings{
		Mode:           int32(resp.GetMode()),
		DestinationDir: resp.GetDestinationDir(),
		PeerRules:      rules,
	}, nil
}

// SetSettings updates the receiving policy of the active profile.
func (s *FileDrop) SetSettings(ctx context.Context, settings FileDropSettings) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.FileDropSetSettings(ctx, &proto.FileDropSetSettingsRequest{
		Mode:           proto.FileDropMode(settings.Mode),
		DestinationDir: settings.DestinationDir,
	})
	return err
}

// SetPeerRule sets or clears a per-sender exception.
func (s *FileDrop) SetPeerRule(ctx context.Context, peerKey string, rule int32) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.FileDropSetPeerRule(ctx, &proto.FileDropSetPeerRuleRequest{
		PeerKey: peerKey,
		Rule:    proto.FileDropRule(rule),
	})
	return err
}

// ClipboardText returns the current clipboard text, empty when unavailable.
func (s *FileDrop) ClipboardText(_ context.Context) string {
	text, ok := application.Get().Clipboard.Text()
	if !ok {
		return ""
	}
	return text
}

// Reveal opens the OS file manager focused on a delivered file.
func (s *FileDrop) Reveal(_ context.Context, path string) error {
	if path == "" {
		return errors.New("empty path")
	}
	return revealFile(path)
}

// Open opens a delivered file with its default application.
func (s *FileDrop) Open(_ context.Context, path string) error {
	if path == "" {
		return errors.New("empty path")
	}
	return openFile(path)
}

func fileDropTransferFromProto(t *proto.FileDropTransfer) FileDropTransfer {
	files := make([]FileDropFile, 0, len(t.GetFiles()))
	for _, f := range t.GetFiles() {
		files = append(files, FileDropFile{
			Name:        f.GetName(),
			Size:        f.GetSize(),
			ContentType: f.GetContentType(),
			IsText:      f.GetIsText(),
			Text:        f.GetText(),
		})
	}
	return FileDropTransfer{
		ID:             t.GetId(),
		Outgoing:       t.GetOutgoing(),
		PeerKey:        t.GetPeerKey(),
		PeerName:       t.GetPeerName(),
		Files:          files,
		State:          int32(t.GetState()),
		Transferred:    t.GetTransferred(),
		TotalSize:      t.GetTotalSize(),
		CreatedAt:      t.GetCreatedAt().AsTime(),
		UpdatedAt:      t.GetUpdatedAt().AsTime(),
		DeliveredPaths: append([]string{}, t.GetDeliveredPaths()...),
		Error:          t.GetError(),
		Reason:         int32(t.GetReason()),
	}
}
