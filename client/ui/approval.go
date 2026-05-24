//go:build !(linux && 386)

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/approval"
	"github.com/netbirdio/netbird/client/proto"
)

// handleApprovalEvent forks a netbird-ui child process to render the
// dialog on its own fyne main loop. Top-level windows opened from a
// background goroutine of the tray process don't render reliably on
// Linux/GTK, so the rest of the UI (settings, login URL, update) uses
// the same fork pattern.
func (s *serviceClient) handleApprovalEvent(ev *proto.SystemEvent) {
	if ev == nil || ev.Category != proto.SystemEvent_APPROVAL {
		return
	}
	requestID := ev.Metadata["request_id"]
	if requestID == "" {
		log.Warnf("approval event missing request_id: %v", ev.Metadata)
		return
	}
	args := []string{
		"--approval-request-id=" + requestID,
		"--approval-kind=" + ev.Metadata["kind"],
		"--approval-initiator=" + ev.Metadata["initiator"],
		"--approval-peer-name=" + ev.Metadata["peer_name"],
		"--approval-source-ip=" + ev.Metadata["source_ip"],
		"--approval-username=" + ev.Metadata["username"],
		"--approval-expires-at=" + ev.Metadata["expires_at"],
		"--approval-key-fingerprint=" + ev.Metadata["peer_pubkey"],
		"--approval-subject=" + ev.UserMessage,
	}
	go s.eventHandler.runSelfCommand(s.ctx, "approval", args...)
}

// showApprovalUI runs the dialog on the forked process's fyne main loop
// and forwards the user's decision to the daemon via RespondApproval.
func (s *serviceClient) showApprovalUI(req approvalRequest) {
	w := s.app.NewWindow(approvalTitle(req.kind))
	w.Resize(fyne.NewSize(480, 260))
	w.CenterOnScreen()
	w.RequestFocus()

	var rows []string
	if req.initiator != "" {
		// The display name comes from the management dashboard and is
		// not cryptographically asserted by the connecting client. The
		// key fingerprint that follows IS: it's the Noise_IK static
		// public key the client just proved possession of. Show both
		// so the user can sanity-check that "Alice" is really the
		// Alice they trust.
		rows = append(rows, "From user:  "+req.initiator)
	}
	if fp := approval.ShortKeyFingerprint(req.keyFingerprint); fp != "" {
		rows = append(rows, "Key fp:     "+fp)
	}
	if req.peerName != "" {
		rows = append(rows, "Via peer:   "+req.peerName)
	}
	if req.sourceIP != "" && req.sourceIP != req.peerName {
		rows = append(rows, "Source IP:  "+req.sourceIP)
	}
	if req.username != "" {
		rows = append(rows, "OS user:    "+req.username)
	}
	if len(rows) == 0 {
		rows = []string{"Remote: " + req.displayPeer()}
	}
	body := strings.Join(rows, "\n")
	bodyLabel := widget.NewLabel(body)
	bodyLabel.Wrapping = fyne.TextWrapWord

	countdown := widget.NewLabel("")
	deadline := req.deadline()
	updateCountdown := func() {
		remaining := time.Until(deadline).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		countdown.SetText(fmt.Sprintf("Auto-deny in %s", remaining))
	}
	updateCountdown()

	type outcome struct {
		accept   bool
		viewOnly bool
	}
	decided := make(chan outcome, 1)
	decide := func(o outcome) {
		select {
		case decided <- o:
		default:
		}
	}

	allow := widget.NewButton("Allow", func() { decide(outcome{accept: true}) })
	allow.Importance = widget.HighImportance
	allowView := widget.NewButton("Allow (view only)", func() { decide(outcome{accept: true, viewOnly: true}) })
	deny := widget.NewButton("Deny", func() { decide(outcome{accept: false}) })

	header := widget.NewLabelWithStyle(req.subject, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	buttonRow := container.NewGridWithColumns(3, allow, allowView, deny)
	info := container.NewVBox(header, widget.NewSeparator(), bodyLabel, widget.NewSeparator(), countdown)
	w.SetContent(container.NewPadded(container.NewBorder(nil, buttonRow, nil, nil, info)))
	w.SetCloseIntercept(func() { decide(outcome{}) })

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if time.Until(deadline) <= 0 {
				decide(outcome{})
				return
			}
			fyne.Do(updateCountdown)
		}
	}()

	go func() {
		o := <-decided
		s.sendApprovalResponse(req.requestID, o.accept, o.viewOnly)
		fyne.Do(func() {
			w.Close()
			s.app.Quit()
		})
	}()

	w.Show()
}

func (s *serviceClient) sendApprovalResponse(requestID string, accept, viewOnly bool) {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Warnf("approval response: get daemon client: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, defaultFailTimeout)
	defer cancel()
	if _, err := conn.RespondApproval(ctx, &proto.RespondApprovalRequest{
		RequestId: requestID,
		Accept:    accept,
		ViewOnly:  viewOnly,
	}); err != nil {
		log.Warnf("approval response: %v", err)
	}
}

// approvalRequest is the parsed --approval-* CLI args that the forked
// dialog process consumes.
type approvalRequest struct {
	requestID      string
	kind           string
	initiator      string
	peerName       string
	sourceIP       string
	username       string
	subject        string
	expiresAt      string
	keyFingerprint string
}

func (r approvalRequest) displayPeer() string {
	switch {
	case r.initiator != "":
		return r.initiator
	case r.peerName != "":
		return r.peerName
	case r.sourceIP != "":
		return r.sourceIP
	default:
		return "unknown peer"
	}
}

// deadline returns the wall-clock auto-deny moment. Falls back to a short
// local window when the daemon's expires_at is missing/unparsable, so a
// stale value never leaves the dialog open indefinitely.
func (r approvalRequest) deadline() time.Time {
	if t, err := time.Parse(time.RFC3339, r.expiresAt); err == nil {
		return t
	}
	return time.Now().Add(13 * time.Second)
}

func approvalTitle(kind string) string {
	switch kind {
	case "vnc":
		return "Allow VNC Connection?"
	case "ssh":
		return "Allow SSH Connection?"
	default:
		return "Allow Incoming Connection?"
	}
}
