package ebpf

import (
	"context"
	"fmt"
	"net"
)

// ProxyWrapper help to keep the remoteConn instance for net.Conn.Close function call
type ProxyWrapper struct {
	WgeBPFProxy *WGEBPFProxy

	remoteConn net.Conn
	cancel     context.CancelFunc
}

func (e *ProxyWrapper) AddTurnConn(ctx context.Context, remoteConn net.Conn) (net.Addr, error) {
	ctxConn, cancel := context.WithCancel(ctx)
	addr, err := e.WgeBPFProxy.AddTurnConn(ctxConn, remoteConn)
	if err != nil {
		cancel()
	}
	e.remoteConn = remoteConn
	e.cancel = cancel
	return addr, err
}

// CloseConn close the remoteConn and automatically remove the conn instance from the map
func (e *ProxyWrapper) CloseConn() error {
	if e.remoteConn == nil {
		return nil
	}

	e.cancel()
	if err := e.remoteConn.Close(); err != nil {
		return fmt.Errorf("failed to close remote conn: %w", err)
	}
	return nil
}
