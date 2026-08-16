//go:build android

package android

import (
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/internal/filedrop"
)

// The file drop receiving modes exported via gomobile.
const (
	FileDropModeOff        = int(filedrop.ModeOff)
	FileDropModeAsk        = int(filedrop.ModeAsk)
	FileDropModeAutoAccept = int(filedrop.ModeAutoAccept)
)

// The per-sender rules exported via gomobile.
const (
	FileDropRuleDefault      = int(filedrop.SenderRuleDefault)
	FileDropRuleAlwaysAccept = int(filedrop.SenderRuleAlwaysAccept)
	FileDropRuleBlock        = int(filedrop.SenderRuleBlock)
)

// The transfer states exported via gomobile.
const (
	FileDropStatePending      = int(filedrop.StatePending)
	FileDropStateTransferring = int(filedrop.StateTransferring)
	FileDropStateCompleted    = int(filedrop.StateCompleted)
	FileDropStateDeclined     = int(filedrop.StateDeclined)
	FileDropStateExpired      = int(filedrop.StateExpired)
	FileDropStateCancelled    = int(filedrop.StateCancelled)
	FileDropStateFailed       = int(filedrop.StateFailed)
)

// The failure reasons exported via gomobile.
const (
	FileDropReasonNone        = int(filedrop.ReasonNone)
	FileDropReasonUnreachable = int(filedrop.ReasonUnreachable)
)

// The event kinds delivered to a FileDropListener.
const (
	FileDropEventOffer     = int(filedrop.EventOffer)
	FileDropEventCompleted = int(filedrop.EventCompleted)
	FileDropEventFailed    = int(filedrop.EventFailed)
	FileDropEventWithdrawn = int(filedrop.EventWithdrawn)
)

// FileDropListener receives transfer events. Calls arrive on background
// goroutines, so implementations must post to the UI thread themselves.
type FileDropListener interface {
	OnFileDropEvent(kind int, transfer *FileDropTransfer)
}

// FileDropFile is one item of a transfer.
type FileDropFile struct {
	Name        string
	Size        int64
	ContentType string
	IsText      bool
	Text        string
}

// FileDropTransfer is one history entry.
type FileDropTransfer struct {
	ID          string
	Outgoing    bool
	PeerKey     string
	PeerName    string
	State       int
	Transferred int64
	TotalSize   int64
	// Unix milliseconds, so the platform layer can render the time in the
	// user's own locale and zone rather than parsing a preformatted string.
	CreatedAtMillis int64
	UpdatedAtMillis int64
	// IsText marks a transfer that is a single inline snippet rather than
	// files, so the UI can drop the size and offer a copy action instead.
	IsText bool
	Error  string
	Reason int

	files          []*FileDropFile
	deliveredPaths []string
}

// FileDropTransferArray wraps transfers for gomobile compatibility.
type FileDropTransferArray struct {
	items []*FileDropTransfer
}

// FileCount returns the number of items in the transfer.
func (t *FileDropTransfer) FileCount() int {
	return len(t.files)
}

// GetFile returns the item at index i, or nil when out of range.
func (t *FileDropTransfer) GetFile(i int) *FileDropFile {
	if i < 0 || i >= len(t.files) {
		return nil
	}
	return t.files[i]
}

// DeliveredPaths returns the delivered file paths joined by newlines, so the
// platform layer can move them into user-visible storage.
func (t *FileDropTransfer) DeliveredPaths() string {
	return strings.Join(t.deliveredPaths, "\n")
}

// Length returns the number of transfers.
func (a *FileDropTransferArray) Length() int {
	return len(a.items)
}

// Get returns the transfer at index i, or nil when out of range.
func (a *FileDropTransferArray) Get(i int) *FileDropTransfer {
	if i < 0 || i >= len(a.items) {
		return nil
	}
	return a.items[i]
}

func toFileDropTransfer(t filedrop.Transfer) *FileDropTransfer {
	files := make([]*FileDropFile, 0, len(t.Files))
	for _, f := range t.Files {
		files = append(files, &FileDropFile{
			Name:        f.Name,
			Size:        f.Size,
			ContentType: f.ContentType,
			IsText:      f.Kind == filedrop.KindText,
			Text:        f.Text,
		})
	}

	return &FileDropTransfer{
		ID:              string(t.ID),
		Outgoing:        t.Direction == filedrop.DirectionSent,
		PeerKey:         string(t.PeerKey),
		PeerName:        t.PeerName,
		State:           int(t.State),
		Transferred:     t.Transferred,
		TotalSize:       t.TotalSize,
		CreatedAtMillis: unixMillis(t.CreatedAt),
		UpdatedAtMillis: unixMillis(t.UpdatedAt),
		IsText:          len(t.Files) == 1 && t.Files[0].Kind == filedrop.KindText,
		Error:           t.Error,
		Reason:          int(t.Reason),
		files:           files,
		deliveredPaths:  t.DeliveredPaths,
	}
}

// unixMillis renders a timestamp for the platform layer, mapping the zero time
// to 0 so it reads as "unknown" rather than as 1970.
func unixMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}
