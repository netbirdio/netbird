//go:build windows

package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/Microsoft/go-winio"
)

const (
	// PipeName is the named pipe path used for IPC between the NetBird agent and
	// the Credential Provider DLL.
	PipeName = `\\.\pipe\netbird-rdp-auth`

	// pipeSDDL restricts access to LOCAL_SYSTEM (SY) and Administrators (BA).
	pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

	// maxPipeRequestSize is the maximum size of a pipe request in bytes.
	maxPipeRequestSize = 4096
)

// windowsPipeServer implements the PipeServer interface for Windows.
type windowsPipeServer struct {
	pending  *PendingStore
	listener net.Listener
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
}

func newPipeServer(pending *PendingStore) PipeServer {
	return &windowsPipeServer{
		pending: pending,
	}
}

func (s *windowsPipeServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ctx, s.cancel = context.WithCancel(ctx)

	cfg := &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL,
	}

	listener, err := winio.ListenPipe(PipeName, cfg)
	if err != nil {
		return err
	}
	s.listener = listener

	go s.acceptLoop()

	log.Infof("RDP named pipe server started on %s", PipeName)
	return nil
}

func (s *windowsPipeServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}

	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		return err
	}
	return nil
}

func (s *windowsPipeServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			log.Debugf("RDP pipe accept error: %v", err)
			continue
		}

		go s.handlePipeConnection(conn)
	}
}

func (s *windowsPipeServer) handlePipeConnection(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			log.Debugf("RDP pipe close: %v", err)
		}
	}()

	data, err := io.ReadAll(io.LimitReader(conn, maxPipeRequestSize))
	if err != nil {
		log.Debugf("RDP pipe read: %v", err)
		return
	}

	var req PipeRequest
	if err := json.Unmarshal(data, &req); err != nil {
		log.Debugf("RDP pipe unmarshal: %v", err)
		return
	}

	var resp PipeResponse

	switch req.Action {
	case PipeActionQuery:
		resp = s.handleQuery(req.RemoteIP)
	case PipeActionConsume:
		resp = s.handleConsume(req.SessionID)
	default:
		log.Debugf("RDP pipe unknown action: %s", req.Action)
		return
	}

	respData, err := json.Marshal(resp)
	if err != nil {
		log.Debugf("RDP pipe marshal response: %v", err)
		return
	}

	if _, err := conn.Write(respData); err != nil {
		log.Debugf("RDP pipe write response: %v", err)
	}
}

func (s *windowsPipeServer) handleQuery(remoteIP string) PipeResponse {
	peerIP, err := parseAddr(remoteIP)
	if err != nil {
		log.Debugf("RDP pipe invalid remote IP: %s", remoteIP)
		return PipeResponse{Found: false}
	}

	session, found := s.pending.QueryByPeerIP(peerIP)
	if !found {
		return PipeResponse{Found: false}
	}

	return PipeResponse{
		Found:     true,
		SessionID: session.SessionID,
		OSUser:    session.OSUsername,
		Domain:    session.Domain,
	}
}

func (s *windowsPipeServer) handleConsume(sessionID string) PipeResponse {
	if s.pending.Consume(sessionID) {
		return PipeResponse{Found: true, SessionID: sessionID}
	}
	return PipeResponse{Found: false}
}
