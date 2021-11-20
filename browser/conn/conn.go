package conn

// credits to https://github.com/rtctunnel/rtctunnel

import (
	"context"
	"errors"
	"github.com/pion/webrtc/v3"
	"io"
	"log"
	"net"
	"time"
)

var ErrClosedByPeer = errors.New("closed by peer")

type DataChannelAddr struct{}

func (addr DataChannelAddr) Network() string {
	return "webrtc"
}

func (addr DataChannelAddr) String() string {
	return "webrtc://datachannel"
}

// A DataChannelConn implements the net.Conn interface over a webrtc data channel
type DataChannelConn struct {
	dc *webrtc.DataChannel
	rr ContextReadCloser
	rw ContextWriteCloser

	openCond  *Cond
	closeCond *Cond
	closeErr  error
}

// WrapDataChannel wraps an rtc data channel and implements the net.Conn
// interface
func WrapDataChannel(rtcDataChannel *webrtc.DataChannel) (*DataChannelConn, error) {
	rr, rw := io.Pipe()

	conn := &DataChannelConn{
		dc: rtcDataChannel,
		rr: ContextReadCloser{Context: context.Background(), ReadCloser: rr},
		rw: ContextWriteCloser{Context: context.Background(), WriteCloser: rw},

		openCond:  NewCond(),
		closeCond: NewCond(),
	}
	conn.dc.OnClose(func() {
		_ = conn.closeWithError(ErrClosedByPeer)
	})
	conn.dc.OnOpen(func() {
		// for reasons I don't understand, when opened the data channel is not immediately available for use
		time.Sleep(50 * time.Millisecond)
		conn.openCond.Signal()
	})
	conn.dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		log.Printf("received message from data channel %d", len(msg.Data))
		if rw != nil {
			_, err := rw.Write(msg.Data)
			if err != nil {
				_ = conn.closeWithError(err)
				rw = nil
			}
		}
	})

	select {
	case <-conn.closeCond.C:
		err := conn.closeErr
		if err == nil {
			err = errors.New("datachannel closed for unknown reasons")
		}
		return nil, err
	case <-conn.openCond.C:
	}

	return conn, nil
}

func (dc *DataChannelConn) Read(b []byte) (n int, err error) {
	return dc.rr.Read(b)
}

func (dc *DataChannelConn) Write(b []byte) (n int, err error) {
	log.Printf("writing buffer of size %d", len(b))
	err = dc.dc.Send(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (dc *DataChannelConn) Close() error {
	return dc.closeWithError(nil)
}

func (dc *DataChannelConn) LocalAddr() net.Addr {
	return DataChannelAddr{}
}

func (dc *DataChannelConn) RemoteAddr() net.Addr {
	return DataChannelAddr{}
}

func (dc *DataChannelConn) SetDeadline(t time.Time) error {
	var err error
	if e := dc.SetReadDeadline(t); e != nil {
		err = e
	}
	if e := dc.SetWriteDeadline(t); e != nil {
		err = e
	}
	return err
}

func (dc *DataChannelConn) SetReadDeadline(t time.Time) error {
	return dc.rr.SetReadDeadline(t)
}

func (dc *DataChannelConn) SetWriteDeadline(t time.Time) error {
	return dc.rw.SetWriteDeadline(t)
}

func (dc *DataChannelConn) closeWithError(err error) error {
	dc.closeCond.Do(func() {
		e := dc.rr.Close()
		if err == nil {
			err = e
		}
		e = dc.rw.Close()
		if err == nil {
			err = e
		}
		e = dc.dc.Close()
		if err == nil {
			err = e
		}
		dc.closeErr = err
	})
	return err
}

type ContextReadCloser struct {
	context.Context
	io.ReadCloser
	cancel func()
}

func (cr ContextReadCloser) Close() error {
	err := cr.ReadCloser.Close()
	if cr.cancel != nil {
		cr.cancel()
		cr.cancel = nil
	}
	return err
}

func (cr ContextReadCloser) SetReadDeadline(t time.Time) error {
	if cr.cancel != nil {
		cr.cancel()
		cr.cancel = nil
	}
	cr.Context, cr.cancel = context.WithDeadline(context.Background(), t)
	return nil
}

func (cr ContextReadCloser) Read(p []byte) (n int, err error) {
	done := make(chan struct{})
	go func() {
		n, err = cr.ReadCloser.Read(p)
		close(done)
	}()
	select {
	case <-done:
		return n, err
	case <-cr.Context.Done():
		return 0, cr.Context.Err()
	}
}

type ContextWriteCloser struct {
	context.Context
	io.WriteCloser
	cancel func()
}

func (cw ContextWriteCloser) Close() error {
	err := cw.WriteCloser.Close()
	if cw.cancel != nil {
		cw.cancel()
		cw.cancel = nil
	}
	return err
}

func (cw ContextWriteCloser) SetWriteDeadline(t time.Time) error {
	if cw.cancel != nil {
		cw.cancel()
		cw.cancel = nil
	}
	cw.Context, cw.cancel = context.WithDeadline(context.Background(), t)
	return nil
}

func (cw ContextWriteCloser) Write(p []byte) (n int, err error) {
	done := make(chan struct{})
	go func() {
		n, err = cw.WriteCloser.Write(p)
		close(done)
	}()
	select {
	case <-done:
		return n, err
	case <-cw.Context.Done():
		return 0, cw.Context.Err()
	}
}
