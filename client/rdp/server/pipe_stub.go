//go:build !windows

package server

import "context"

type stubPipeServer struct{}

func newPipeServer(_ *PendingStore) PipeServer {
	return &stubPipeServer{}
}

func (s *stubPipeServer) Start(_ context.Context) error {
	return nil
}

func (s *stubPipeServer) Stop() error {
	return nil
}
