//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/ui/services"
)

const (
	notifyCategoryFileDropOffer = "netbird-filedrop-offer"
	notifyActionFileDropAccept  = "filedrop-accept"
	notifyActionFileDropDecline = "filedrop-decline"
	notifyActionFileDropAlways  = "filedrop-always-accept"
	notifyIDFileDropPrefix      = "netbird-filedrop-"

	fileDropDecideTimeout = 10 * time.Second
)

// registerFileDropCategory wires the consent-notification category. Errors are
// swallowed: the worst case is a plain notification without buttons.
func (t *Tray) registerFileDropCategory() {
	if t.svc.Notifier == nil {
		return
	}
	if err := t.svc.Notifier.RegisterNotificationCategory(notifications.NotificationCategory{
		ID: notifyCategoryFileDropOffer,
		Actions: []notifications.NotificationAction{
			{ID: notifyActionFileDropAccept, Title: t.loc.T("files.offer.accept")},
			{ID: notifyActionFileDropDecline, Title: t.loc.T("files.offer.decline")},
			{ID: notifyActionFileDropAlways, Title: t.loc.T("notify.filedrop.always")},
		},
	}); err != nil {
		log.Debugf("register file drop notification category: %v", err)
	}
}

// notifyFileDropOffer raises the consent notification with Accept, Decline, and
// Always accept actions, falling back to a plain notification.
func (t *Tray) notifyFileDropOffer(se services.SystemEvent) {
	if t.svc.Notifier == nil {
		return
	}

	transferID := se.Metadata[proto.MetadataFileDropTransferKey]
	title := t.loc.T("notify.filedrop.offer.title")
	if transferID == "" {
		t.notify(title, se.UserMessage, notifyIDEvent+se.ID)
		return
	}

	err := safeSendNotification(t.svc.Notifier.SendNotificationWithActions, "filedrop offer with actions", notifications.NotificationOptions{
		ID:         notifyIDFileDropPrefix + transferID,
		Title:      title,
		Body:       se.UserMessage,
		CategoryID: notifyCategoryFileDropOffer,
		Data: map[string]interface{}{
			proto.MetadataFileDropTransferKey: transferID,
			proto.MetadataFileDropPeerKey:     se.Metadata[proto.MetadataFileDropPeerKey],
		},
	})
	if err != nil {
		t.notify(title, se.UserMessage, notifyIDFileDropPrefix+transferID)
	}
}

// handleFileDropResponse acts on the consent-notification buttons. The transfer ID
// is recovered from the notification ID when the platform drops the user info; a
// body click just brings the app forward, so a stray tap can never accept.
func (t *Tray) handleFileDropResponse(resp notifications.NotificationResponse) {
	transferID, _ := resp.UserInfo[proto.MetadataFileDropTransferKey].(string)
	if transferID == "" && strings.HasPrefix(resp.ID, notifyIDFileDropPrefix) {
		transferID = strings.TrimPrefix(resp.ID, notifyIDFileDropPrefix)
	}
	peerKey, _ := resp.UserInfo[proto.MetadataFileDropPeerKey].(string)

	switch resp.ActionIdentifier {
	case notifyActionFileDropAccept:
		go t.fileDropDecide(transferID, true)
	case notifyActionFileDropDecline:
		go t.fileDropDecide(transferID, false)
	case notifyActionFileDropAlways:
		go t.fileDropAlwaysAccept(transferID, peerKey)
	default:
		t.ShowWindow()
	}
}

// onFileDropEvent withdraws the consent notification when the sender cancelled the
// offer or it expired.
func (t *Tray) onFileDropEvent(ev *application.CustomEvent) {
	fe, ok := ev.Data.(services.FileDropEvent)
	if !ok || fe.Kind != "withdrawn" || fe.TransferID == "" {
		return
	}
	t.removeFileDropNotification(fe.TransferID)
}

func (t *Tray) fileDropDecide(transferID string, accept bool) {
	if t.svc.FileDrop == nil || transferID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), fileDropDecideTimeout)
	defer cancel()
	if err := t.svc.FileDrop.Decide(ctx, transferID, accept); err != nil {
		log.Debugf("file drop decide from notification: %v", err)
	}
}

func (t *Tray) fileDropAlwaysAccept(transferID, peerKey string) {
	if t.svc.FileDrop == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), fileDropDecideTimeout)
	defer cancel()
	if peerKey != "" {
		if err := t.svc.FileDrop.SetPeerRule(ctx, peerKey, int32(proto.FileDropRule_FILE_DROP_RULE_ALWAYS)); err != nil {
			log.Debugf("file drop always-accept rule from notification: %v", err)
		}
	}
	t.fileDropDecide(transferID, true)
}

// removeFileDropNotification is panic-guarded like safeSendNotification: a dead
// notification bus on Linux panics inside godbus on any call.
func (t *Tray) removeFileDropNotification(transferID string) {
	if t.svc.Notifier == nil || services.ShuttingDown() {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("remove filedrop notification: recovered from panic (notification bus unavailable): %v", r)
		}
	}()
	if err := t.svc.Notifier.RemoveNotification(notifyIDFileDropPrefix + transferID); err != nil {
		log.Debugf("remove filedrop notification: %v", err)
	}
}
