package dialer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

type MockAddr struct {
	network string
}

func (m *MockAddr) Network() string {
	return m.network
}

func (m *MockAddr) String() string {
	return "1.2.3.4"
}

// MockDialer is a mock implementation of DialeFn
type MockDialer struct {
	dialFunc    func(ctx context.Context, address string) (net.Conn, error)
	protocolStr string
}

func (m *MockDialer) Dial(ctx context.Context, address string) (net.Conn, error) {
	return m.dialFunc(ctx, address)
}

func (m *MockDialer) Protocol() string {
	return m.protocolStr
}

// MockConn implements net.Conn for testing
type MockConn struct {
	remoteAddr net.Addr
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	return 0, nil
}

func (m *MockConn) Close() error {
	return nil
}

func (m *MockConn) LocalAddr() net.Addr {
	return nil
}

func (m *MockConn) RemoteAddr() net.Addr {
	return m.remoteAddr
}

func (m *MockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestRaceDialEmptyDialers(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	serverURL := "test.server.com"

	rd := NewRaceDial(logger, DefaultConnectionTimeout, serverURL)
	conn, err := rd.Dial()
	if err == nil {
		t.Errorf("Expected an error with empty dialers, got nil")
	}
	if conn != nil {
		t.Errorf("Expected nil connection with empty dialers, got %v", conn)
	}
}

func TestRaceDialSingleSuccessfulDialer(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	serverURL := "test.server.com"
	proto := "test-protocol"

	mockConn := &MockConn{
		remoteAddr: &MockAddr{network: proto},
	}

	mockDialer := &MockDialer{
		dialFunc: func(ctx context.Context, address string) (net.Conn, error) {
			return mockConn, nil
		},
		protocolStr: proto,
	}

	rd := NewRaceDial(logger, DefaultConnectionTimeout, serverURL, mockDialer)
	conn, err := rd.Dial()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if conn == nil {
		t.Errorf("Expected non-nil connection")
	}
}

func TestRaceDialMultipleDialersWithOneSuccess(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	serverURL := "test.server.com"
	proto2 := "protocol2"

	mockConn2 := &MockConn{
		remoteAddr: &MockAddr{network: proto2},
	}

	mockDialer1 := &MockDialer{
		dialFunc: func(ctx context.Context, address string) (net.Conn, error) {
			return nil, errors.New("first dialer failed")
		},
		protocolStr: "proto1",
	}

	mockDialer2 := &MockDialer{
		dialFunc: func(ctx context.Context, address string) (net.Conn, error) {
			return mockConn2, nil
		},
		protocolStr: "proto2",
	}

	rd := NewRaceDial(logger, DefaultConnectionTimeout, serverURL, mockDialer1, mockDialer2)
	conn, err := rd.Dial()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if conn.RemoteAddr().Network() != proto2 {
		t.Errorf("Expected connection with protocol %s, got %s", proto2, conn.RemoteAddr().Network())
	}
	_ = conn.Close()
}

func TestRaceDialTimeout(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	serverURL := "test.server.com"

	mockDialer := &MockDialer{
		dialFunc: func(ctx context.Context, address string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		protocolStr: "proto1",
	}

	rd := NewRaceDial(logger, 3*time.Second, serverURL, mockDialer)
	conn, err := rd.Dial()
	if err == nil {
		t.Errorf("Expected an error, got nil")
	}
	if conn != nil {
		t.Errorf("Expected nil connection, got %v", conn)
	}
}

func TestRaceDialAllDialersFail(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	serverURL := "test.server.com"

	mockDialer1 := &MockDialer{
		dialFunc: func(ctx context.Context, address string) (net.Conn, error) {
			return nil, errors.New("first dialer failed")
		},
		protocolStr: "protocol1",
	}

	mockDialer2 := &MockDialer{
		dialFunc: func(ctx context.Context, address string) (net.Conn, error) {
			return nil, errors.New("second dialer failed")
		},
		protocolStr: "protocol2",
	}

	rd := NewRaceDial(logger, DefaultConnectionTimeout, serverURL, mockDialer1, mockDialer2)
	conn, err := rd.Dial()
	if err == nil {
		t.Errorf("Expected an error, got nil")
	}
	if conn != nil {
		t.Errorf("Expected nil connection, got %v", conn)
	}
}

func TestRaceDialFirstSuccessfulDialerWins(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	serverURL := "test.server.com"
	proto1 := "protocol1"
	proto2 := "protocol2"

	mockConn1 := &MockConn{
		remoteAddr: &MockAddr{network: proto1},
	}

	mockConn2 := &MockConn{
		remoteAddr: &MockAddr{network: proto2},
	}

	mockDialer1 := &MockDialer{
		dialFunc: func(ctx context.Context, address string) (net.Conn, error) {
			time.Sleep(1 * time.Second)
			return mockConn1, nil
		},
		protocolStr: proto1,
	}

	mock2err := make(chan error)
	mockDialer2 := &MockDialer{
		dialFunc: func(ctx context.Context, address string) (net.Conn, error) {
			<-ctx.Done()
			mock2err <- ctx.Err()
			return mockConn2, ctx.Err()
		},
		protocolStr: proto2,
	}

	rd := NewRaceDial(logger, DefaultConnectionTimeout, serverURL, mockDialer1, mockDialer2)
	conn, err := rd.Dial()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if conn == nil {
		t.Errorf("Expected non-nil connection")
	}
	if conn != mockConn1 {
		t.Errorf("Expected first connection, got %v", conn)
	}

	select {
	case <-time.After(3 * time.Second):
		t.Errorf("Timed out waiting for second dialer to finish")
	case err := <-mock2err:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Expected context.Canceled error, got %v", err)
		}
	}
}
