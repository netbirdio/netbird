package dns

import (
	"github.com/miekg/dns"
	"net"
)

type mockResponseWriter struct {
	WriteMsgFunc func(m *dns.Msg) error
}

func (rw *mockResponseWriter) WriteMsg(m *dns.Msg) error {
	if rw.WriteMsgFunc != nil {
		return rw.WriteMsgFunc(m)
	}
	return nil
}

func (rw *mockResponseWriter) LocalAddr() net.Addr       { return nil }
func (rw *mockResponseWriter) RemoteAddr() net.Addr      { return nil }
func (rw *mockResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (rw *mockResponseWriter) Close() error              { return nil }
func (rw *mockResponseWriter) TsigStatus() error         { return nil }
func (rw *mockResponseWriter) TsigTimersOnly(bool)       {}
func (rw *mockResponseWriter) Hijack()                   {}

type mockHostManager struct {
	applyDNSConfigFunc func(config hostDNSConfig) error
	restoreHostDNSFunc func() error
}

func (hm *mockHostManager) applyDNSConfig(config hostDNSConfig) error {
	return hm.applyDNSConfigFunc(config)
}

func (hm *mockHostManager) restoreHostDNS() error {
	return hm.restoreHostDNSFunc()
}
