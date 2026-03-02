//go:build !(linux && 386)

package event

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/version"
)

// NotifyFunc is a callback used to send desktop notifications.
type NotifyFunc func(title, body string)

// Handler is a callback invoked for each received daemon event.
type Handler func(*proto.SystemEvent)

// Manager subscribes to daemon events and dispatches them.
type Manager struct {
	addr   string
	notify NotifyFunc

	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	enabled  bool
	handlers []Handler

	connMu sync.Mutex
	conn   *grpc.ClientConn
	client proto.DaemonServiceClient
}

// NewManager creates a new event Manager.
func NewManager(addr string, notify NotifyFunc) *Manager {
	return &Manager{
		addr:   addr,
		notify: notify,
	}
}

// Start begins event streaming with exponential backoff reconnection.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.mu.Unlock()

	expBackOff := backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     time.Second,
		RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier:          backoff.DefaultMultiplier,
		MaxInterval:         10 * time.Second,
		MaxElapsedTime:      0,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)

	if err := backoff.Retry(m.streamEvents, expBackOff); err != nil {
		log.Errorf("event stream ended: %v", err)
	}
}

func (m *Manager) streamEvents() error {
	m.mu.Lock()
	ctx := m.ctx
	m.mu.Unlock()

	client, err := m.getClient()
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	stream, err := client.SubscribeEvents(ctx, &proto.SubscribeRequest{})
	if err != nil {
		return fmt.Errorf("subscribe events: %w", err)
	}

	log.Info("subscribed to daemon events")
	defer log.Info("unsubscribed from daemon events")

	for {
		event, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("receive event: %w", err)
		}
		m.handleEvent(event)
	}
}

// Stop cancels the event stream and closes the connection.
func (m *Manager) Stop() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Unlock()

	m.connMu.Lock()
	if m.conn != nil {
		m.conn.Close()
		m.conn = nil
		m.client = nil
	}
	m.connMu.Unlock()
}

// SetNotificationsEnabled enables or disables desktop notifications.
func (m *Manager) SetNotificationsEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = enabled
}

// AddHandler registers an event handler.
func (m *Manager) AddHandler(h Handler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, h)
}

func (m *Manager) handleEvent(event *proto.SystemEvent) {
	m.mu.Lock()
	enabled := m.enabled
	handlers := slices.Clone(m.handlers)
	m.mu.Unlock()

	// Critical events are always shown.
	if !enabled && event.Severity != proto.SystemEvent_CRITICAL {
		goto dispatch
	}

	if event.UserMessage != "" && m.notify != nil {
		title := getEventTitle(event)
		body := event.UserMessage
		if id := event.Metadata["id"]; id != "" {
			body += fmt.Sprintf(" ID: %s", id)
		}
		m.notify(title, body)
	}

dispatch:
	for _, h := range handlers {
		go h(event)
	}
}

func getEventTitle(event *proto.SystemEvent) string {
	var prefix string
	switch event.Severity {
	case proto.SystemEvent_CRITICAL:
		prefix = "Critical"
	case proto.SystemEvent_ERROR:
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

// getClient returns a cached gRPC client, creating the connection on first use.
func (m *Manager) getClient() (proto.DaemonServiceClient, error) {
	m.connMu.Lock()
	defer m.connMu.Unlock()

	if m.client != nil {
		return m.client, nil
	}

	target := m.addr
	if strings.HasPrefix(target, "tcp://") {
		target = strings.TrimPrefix(target, "tcp://")
	} else if strings.HasPrefix(target, "unix://") {
		target = "unix:" + strings.TrimPrefix(target, "unix://")
	}

	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUserAgent("netbird-fancyui/"+version.NetbirdVersion()),
	)
	if err != nil {
		return nil, err
	}

	m.conn = conn
	m.client = proto.NewDaemonServiceClient(conn)
	log.Debugf("event manager: gRPC connection established to %s", m.addr)

	return m.client, nil
}
