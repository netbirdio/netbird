//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"errors"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"
)

var errNotificationsUnavailable = errors.New("notifications unavailable")

// Notifier wraps the Wails notification service so an unavailable backend
// disables notifications instead of aborting the app. Startup fails for
// environment reasons (a bare unbundled binary on macOS has no bundle
// identifier, a headless Linux session has no D-Bus session bus), and Wails
// treats a service startup error as fatal. After a failed startup every call
// is a no-op: on macOS, touching UNUserNotificationCenter without a bundle
// identifier raises an Objective-C exception that recover() cannot catch.
type Notifier struct {
	inner     *notifications.NotificationService
	available atomic.Bool
}

func newNotifier() *Notifier {
	return &Notifier{inner: notifications.New()}
}

// ServiceName implements the Wails service-name hook for startup logs.
func (n *Notifier) ServiceName() string {
	return n.inner.ServiceName()
}

// ServiceStartup starts the platform notifier, downgrading failure to a
// warning so the app keeps running without notifications.
func (n *Notifier) ServiceStartup(ctx context.Context, options application.ServiceOptions) error {
	if err := n.inner.ServiceStartup(ctx, options); err != nil {
		log.Warnf("notifications disabled: %v", err)
		return nil
	}
	n.available.Store(true)
	return nil
}

func (n *Notifier) ServiceShutdown() error {
	if !n.available.Load() {
		return nil
	}
	return n.inner.ServiceShutdown()
}

func (n *Notifier) CheckNotificationAuthorization() (bool, error) {
	if !n.available.Load() {
		return false, errNotificationsUnavailable
	}
	return n.inner.CheckNotificationAuthorization()
}

func (n *Notifier) RequestNotificationAuthorization() (bool, error) {
	if !n.available.Load() {
		return false, errNotificationsUnavailable
	}
	return n.inner.RequestNotificationAuthorization()
}

// SendNotification delivers a notification, silently dropping it when the
// backend never started (notifications are best-effort everywhere).
func (n *Notifier) SendNotification(options notifications.NotificationOptions) error {
	if !n.available.Load() {
		log.Debugf("notifications disabled, dropping %q", options.ID)
		return nil
	}
	return n.inner.SendNotification(options)
}

func (n *Notifier) SendNotificationWithActions(options notifications.NotificationOptions) error {
	if !n.available.Load() {
		log.Debugf("notifications disabled, dropping %q", options.ID)
		return nil
	}
	return n.inner.SendNotificationWithActions(options)
}

// RemoveNotification withdraws a delivered notification, a no-op without a backend.
func (n *Notifier) RemoveNotification(identifier string) error {
	if !n.available.Load() {
		return nil
	}
	return n.inner.RemoveNotification(identifier)
}

func (n *Notifier) RegisterNotificationCategory(category notifications.NotificationCategory) error {
	if !n.available.Load() {
		return nil
	}
	return n.inner.RegisterNotificationCategory(category)
}

// OnNotificationResponse registers the response callback. Pure Go state, so
// it is safe (and simply inert) when the backend never started.
//
//wails:ignore
func (n *Notifier) OnNotificationResponse(callback func(result notifications.NotificationResult)) {
	n.inner.OnNotificationResponse(callback)
}
