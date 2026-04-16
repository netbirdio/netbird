package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	nbgrpc "github.com/netbirdio/netbird/client/grpc"
	"github.com/netbirdio/netbird/flow/proto"
	"github.com/netbirdio/netbird/util/embeddedroots"
	"github.com/netbirdio/netbird/util/wsproxy"
)

var ErrClientClosed = errors.New("client is closed")

// minHealthyDuration is the minimum time a stream must survive before a failure
// resets the backoff timer. Streams that fail faster are considered unhealthy and
// should not reset backoff, so that MaxElapsedTime can eventually stop retries.
const minHealthyDuration = 5 * time.Second

type GRPCClient struct {
	realClient proto.FlowServiceClient
	clientConn *grpc.ClientConn
	stream     proto.FlowService_EventsClient
	target     string
	opts       []grpc.DialOption
	closed     bool       // prevent creating conn in the middle of the Close
	receiving  bool       // prevent concurrent Receive calls
	mu         sync.Mutex // protects clientConn, realClient, stream, closed, and receiving
}

func NewClient(addr, payload, signature string, interval time.Duration) (*GRPCClient, error) {
	parsedURL, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("parsing url: %w", err)
	}
	var opts []grpc.DialOption
	tlsEnabled := parsedURL.Scheme == "https"
	if tlsEnabled {
		certPool, err := x509.SystemCertPool()
		if err != nil || certPool == nil {
			log.Debugf("System cert pool not available; falling back to embedded cert, error: %v", err)
			certPool = embeddedroots.Get()
		}

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs: certPool,
		})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	opts = append(opts,
		nbgrpc.WithCustomDialer(tlsEnabled, wsproxy.FlowComponent),
		grpc.WithIdleTimeout(interval*2),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		withAuthToken(payload, signature),
		grpc.WithDefaultServiceConfig(`{"healthCheckConfig": {"serviceName": ""}}`),
	)

	target := parsedURL.Host
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating new grpc client: %w", err)
	}

	return &GRPCClient{
		realClient: proto.NewFlowServiceClient(conn),
		clientConn: conn,
		target:     target,
		opts:       opts,
	}, nil
}

func (c *GRPCClient) Close() error {
	c.mu.Lock()
	c.closed = true
	c.stream = nil
	conn := c.clientConn
	c.clientConn = nil
	c.mu.Unlock()

	if conn == nil {
		return nil
	}

	if err := conn.Close(); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("close client connection: %w", err)
	}

	return nil
}

func (c *GRPCClient) Send(event *proto.FlowEvent) error {
	c.mu.Lock()
	stream := c.stream
	c.mu.Unlock()

	if stream == nil {
		return errors.New("stream not initialized")
	}

	if err := stream.Send(event); err != nil {
		return fmt.Errorf("send flow event: %w", err)
	}

	return nil
}

func (c *GRPCClient) Receive(ctx context.Context, interval time.Duration, msgHandler func(msg *proto.FlowEventAck) error) error {
	c.mu.Lock()
	if c.receiving {
		c.mu.Unlock()
		return errors.New("concurrent Receive calls are not supported")
	}
	c.receiving = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.receiving = false
		c.mu.Unlock()
	}()

	backOff := defaultBackoff(ctx, interval)
	operation := func() error {
		stream, err := c.establishStream(ctx)
		if err != nil {
			log.Errorf("failed to establish flow stream, retrying: %v", err)
			return c.handleRetryableError(err, time.Time{}, backOff)
		}

		streamStart := time.Now()

		if err := c.receive(stream, msgHandler); err != nil {
			log.Errorf("receive failed: %v", err)
			return c.handleRetryableError(err, streamStart, backOff)
		}
		return nil
	}

	if err := backoff.Retry(operation, backOff); err != nil {
		return fmt.Errorf("receive failed permanently: %w", err)
	}

	return nil
}

// handleRetryableError resets the backoff timer if the stream was healthy long
// enough and recreates the underlying ClientConn so that gRPC's internal
// subchannel backoff does not accumulate and compete with our own retry timer.
// A zero streamStart means the stream was never established.
func (c *GRPCClient) handleRetryableError(err error, streamStart time.Time, backOff backoff.BackOff) error {
	if isContextDone(err) {
		return backoff.Permanent(err)
	}

	var permErr *backoff.PermanentError
	if errors.As(err, &permErr) {
		return err
	}

	// Reset the backoff so the next retry starts with a short delay instead of
	// continuing the already-elapsed timer. Only do this if the stream was healthy
	// long enough; short-lived connect/drop cycles must not defeat MaxElapsedTime.
	if !streamStart.IsZero() && time.Since(streamStart) >= minHealthyDuration {
		backOff.Reset()
	}

	if recreateErr := c.recreateConnection(); recreateErr != nil {
		log.Errorf("recreate connection: %v", recreateErr)
		return recreateErr
	}

	log.Infof("connection recreated, retrying stream")
	return fmt.Errorf("retrying after error: %w", err)
}

func (c *GRPCClient) recreateConnection() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return backoff.Permanent(ErrClientClosed)
	}

	conn, err := grpc.NewClient(c.target, c.opts...)
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("create new connection: %w", err)
	}

	old := c.clientConn
	c.clientConn = conn
	c.realClient = proto.NewFlowServiceClient(conn)
	c.stream = nil
	c.mu.Unlock()

	_ = old.Close()

	return nil
}

func (c *GRPCClient) establishStream(ctx context.Context) (proto.FlowService_EventsClient, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, backoff.Permanent(ErrClientClosed)
	}
	cl := c.realClient
	c.mu.Unlock()

	// open stream outside the lock — blocking operation
	stream, err := cl.Events(ctx)
	if err != nil {
		return nil, fmt.Errorf("create event stream: %w", err)
	}
	streamReady := false
	defer func() {
		if !streamReady {
			_ = stream.CloseSend()
		}
	}()

	if err = stream.Send(&proto.FlowEvent{IsInitiator: true}); err != nil {
		return nil, fmt.Errorf("send initiator: %w", err)
	}

	if err = checkHeader(stream); err != nil {
		return nil, fmt.Errorf("check header: %w", err)
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, backoff.Permanent(ErrClientClosed)
	}
	c.stream = stream
	c.mu.Unlock()
	streamReady = true

	return stream, nil
}

func (c *GRPCClient) receive(stream proto.FlowService_EventsClient, msgHandler func(msg *proto.FlowEventAck) error) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}

		if msg.IsInitiator {
			log.Tracef("received initiator message from flow receiver")
			continue
		}

		if err := msgHandler(msg); err != nil {
			return fmt.Errorf("handle message: %w", err)
		}
	}
}

func checkHeader(stream proto.FlowService_EventsClient) error {
	header, err := stream.Header()
	if err != nil {
		log.Errorf("waiting for flow receiver header: %s", err)
		return fmt.Errorf("wait for header: %w", err)
	}

	if len(header) == 0 {
		log.Error("flow receiver sent no headers")
		return fmt.Errorf("should have headers")
	}
	return nil
}

func defaultBackoff(ctx context.Context, interval time.Duration) backoff.BackOff {
	return backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     800 * time.Millisecond,
		RandomizationFactor: 0.5,
		Multiplier:          1.7,
		MaxInterval:         interval / 2,
		MaxElapsedTime:      3 * 30 * 24 * time.Hour, // 3 months
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)
}

func isContextDone(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if s, ok := status.FromError(err); ok {
		return s.Code() == codes.Canceled || s.Code() == codes.DeadlineExceeded
	}
	return false
}
