package event

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/ui/desktop"
)

type Manager struct {
	app  fyne.App
	addr string

	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	enabled bool
}

func NewManager(app fyne.App, addr string) *Manager {
	return &Manager{
		app:  app,
		addr: addr,
	}
}

func (e *Manager) Start(ctx context.Context) {
	e.mu.Lock()
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.mu.Unlock()

	expBackOff := backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     time.Second,
		RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier:          backoff.DefaultMultiplier,
		MaxInterval:         10 * time.Second,
		MaxElapsedTime:      0,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)

	if err := backoff.Retry(e.streamEvents, expBackOff); err != nil {
		log.Errorf("event stream ended: %v", err)
	}
}

func (e *Manager) streamEvents() error {
	e.mu.Lock()
	ctx := e.ctx
	e.mu.Unlock()

	client, err := getClient(e.addr)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	stream, err := client.SubscribeEvents(ctx, &proto.SubscribeRequest{})
	if err != nil {
		return fmt.Errorf("failed to subscribe to events: %w", err)
	}

	log.Info("subscribed to daemon events")
	defer func() {
		log.Info("unsubscribed from daemon events")
	}()

	for {
		event, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("error receiving event: %w", err)
		}
		e.handleEvent(event)
	}
}

func (e *Manager) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancel != nil {
		e.cancel()
	}
}

func (e *Manager) SetNotificationsEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = enabled
}

func (e *Manager) handleEvent(event *proto.SystemEvent) {
	e.mu.Lock()
	enabled := e.enabled
	e.mu.Unlock()

	if !enabled {
		return
	}

	title := e.getEventTitle(event)
	e.app.SendNotification(fyne.NewNotification(title, event.UserMessage))
}

func (e *Manager) getEventTitle(event *proto.SystemEvent) string {
	var prefix string
	switch event.Severity {
	case proto.SystemEvent_ERROR, proto.SystemEvent_CRITICAL:
		prefix = "Error"
	case proto.SystemEvent_WARNING:
		prefix = "Warning"
	default:
		prefix = "Info"
	}

	var category string
	switch event.Category {
	case proto.SystemEvent_DNS:
		category = "DNS"
	case proto.SystemEvent_NETWORK:
		category = "Network"
	case proto.SystemEvent_AUTHENTICATION:
		category = "Authentication"
	case proto.SystemEvent_CONNECTIVITY:
		category = "Connectivity"
	default:
		category = "System"
	}

	return fmt.Sprintf("%s: %s", prefix, category)
}

func getClient(addr string) (proto.DaemonServiceClient, error) {
	conn, err := grpc.NewClient(
		strings.TrimPrefix(addr, "tcp://"),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUserAgent(desktop.GetUIUserAgent()),
	)
	if err != nil {
		return nil, err
	}
	return proto.NewDaemonServiceClient(conn), nil
}
