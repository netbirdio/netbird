package ssh

import "context"

// MockServer mocks ssh.Server
type MockServer struct {
	Ctx                     context.Context
	StopFunc                func() error
	StartFunc               func() error
	AddAuthorizedKeyFunc    func(peer, newKey string) error
	RemoveAuthorizedKeyFunc func(peer string)
}

// RemoveAuthorizedKey removes SSH key of a given peer from the authorized keys
func (srv *MockServer) RemoveAuthorizedKey(peer string) {
	if srv.RemoveAuthorizedKeyFunc == nil {
		return
	}
	srv.RemoveAuthorizedKeyFunc(peer)
}

// AddAuthorizedKey add a given peer key to server authorized keys
func (srv *MockServer) AddAuthorizedKey(peer, newKey string) error {
	if srv.AddAuthorizedKeyFunc == nil {
		return nil
	}
	return srv.AddAuthorizedKeyFunc(peer, newKey)
}

// Stop stops SSH server.
func (srv *MockServer) Stop() error {
	if srv.StopFunc == nil {
		return nil
	}
	return srv.StopFunc()
}

// Start starts SSH server. Blocking
func (srv *MockServer) Start() error {
	if srv.StartFunc == nil {
		return nil
	}
	return srv.StartFunc()
}
