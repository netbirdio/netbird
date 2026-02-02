package test

import (
	"net"

	"github.com/miekg/dns"
)

type MockResponseWriter struct {
	WriteMsgFunc func(m *dns.Msg) error
	lastResponse *dns.Msg
}

func (rw *MockResponseWriter) WriteMsg(m *dns.Msg) error {
	rw.lastResponse = m
	if rw.WriteMsgFunc != nil {
		return rw.WriteMsgFunc(m)
	}
	return nil
}

func (rw *MockResponseWriter) GetLastResponse() *dns.Msg {
	return rw.lastResponse
}

func (rw *MockResponseWriter) LocalAddr() net.Addr       { return nil }
func (rw *MockResponseWriter) RemoteAddr() net.Addr      { return nil }
func (rw *MockResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (rw *MockResponseWriter) Close() error              { return nil }
func (rw *MockResponseWriter) TsigStatus() error         { return nil }
func (rw *MockResponseWriter) TsigTimersOnly(bool)       {}
func (rw *MockResponseWriter) Hijack()                   {}
