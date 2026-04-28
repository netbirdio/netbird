package recordwriter

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// rfc2136TestServer is a small in-memory authoritative DNS server we point
// the writer at. It exchanges real DNS messages so we exercise the whole
// stack — TSIG signing, UPDATE encoding, response decoding — not just our
// own logic.
//
// Tests configure the handler with a closure that inspects each query and
// returns the desired response, plus a matching TSIG secret so signed
// requests verify.
type rfc2136TestServer struct {
	addr     string
	srv      *dns.Server
	shutdown func()
}

const (
	testKeyName    = "auto-config."           // FQDN form
	testAlgorithm  = "hmac-sha256."           // FQDN form
	testTSIGSecret = "Kzqq+jE3+1xX8b5Yk5Rqfg==" // base64, arbitrary 16-byte sample
)

// startTestServer spins up an in-process TCP DNS server on 127.0.0.1:<random>
// with the given handler and TSIG secret loaded so signed UPDATEs verify.
// Returns the addr the writer should dial. Caller must call shutdown when
// done.
func startTestServer(t *testing.T, handler dns.HandlerFunc) *rfc2136TestServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", handler)

	started := make(chan struct{})
	srv := &dns.Server{
		Listener:   ln,
		Handler:    mux,
		TsigSecret: map[string]string{testKeyName: testTSIGSecret},
		// The default MsgAcceptFunc rejects OpcodeUpdate ("don't allow
		// dynamic updates, because then the sections can contain a whole
		// bunch of RRs"). Override to accept everything our writer might
		// send so we exercise the real UPDATE path.
		MsgAcceptFunc:     func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept },
		NotifyStartedFunc: func() { close(started) },
	}

	done := make(chan error, 1)
	go func() {
		done <- srv.ActivateAndServe()
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for test server to start")
	}

	return &rfc2136TestServer{
		addr: ln.Addr().String(),
		srv:  srv,
		shutdown: func() {
			_ = srv.Shutdown()
			<-done
		},
	}
}

// newTestRFC2136Writer builds a writer pointed at a running test server
// with the matching TSIG secret. The algorithm input is intentionally the
// user-friendly "hmac-sha256" form (no trailing dot) so we exercise the
// builder's normalization in every test.
func newTestRFC2136Writer(t *testing.T, addr string) *rfc2136Writer {
	t.Helper()
	w, err := buildRFC2136Writer(map[string]string{
		"nameserver":     addr,
		"tsig_algorithm": "hmac-sha256", // unfqdn — builder must normalize
		"tsig_key":       "auto-config", // unfqdn — builder must normalize
		"tsig_secret":    testTSIGSecret,
	})
	if err != nil {
		t.Fatalf("buildRFC2136Writer: %v", err)
	}
	return w.(*rfc2136Writer)
}

// soaRR builds a synthetic SOA RR for a zone — enough to satisfy our zone
// resolution check, which only looks at len(resp.Answer).
func soaRR(zone string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1." + dns.Fqdn(zone),
		Mbox:    "hostmaster." + dns.Fqdn(zone),
		Serial:  1,
		Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
	}
}

// signReply finalizes a reply by copying the request's TSIG so the response
// is properly signed (or unsigned if the request was unsigned). The miekg
// server takes care of computing the MAC when the handler writes the msg.
func signReply(req, reply *dns.Msg) {
	if t := req.IsTsig(); t != nil {
		reply.SetTsig(t.Hdr.Name, t.Algorithm, 300, time.Now().Unix())
	}
}

// --------------------------------------------------------------------------
// Tests

func TestRFC2136Writer_BuildRequiresAllFields(t *testing.T) {
	full := map[string]string{
		"nameserver":     "ns1.example.com:53",
		"tsig_algorithm": "hmac-sha256",
		"tsig_key":       "auto-config",
		"tsig_secret":    testTSIGSecret,
	}
	if _, err := buildRFC2136Writer(full); err != nil {
		t.Fatalf("full map should build: %v", err)
	}
	// Every required field must trigger a build error when absent.
	for _, missing := range []string{"nameserver", "tsig_algorithm", "tsig_key", "tsig_secret"} {
		copyMap := make(map[string]string, len(full))
		for k, v := range full {
			if k != missing {
				copyMap[k] = v
			}
		}
		if _, err := buildRFC2136Writer(copyMap); err == nil {
			t.Errorf("expected error when %q is missing", missing)
		}
	}
}

func TestRFC2136Writer_RegistersAtInit(t *testing.T) {
	if _, err := BuildRecordWriter("rfc2136", map[string]string{
		"nameserver":     "ns1.example.com:53",
		"tsig_algorithm": "hmac-sha256",
		"tsig_key":       "auto-config",
		"tsig_secret":    testTSIGSecret,
	}); err != nil {
		t.Fatalf("expected rfc2136 to be registered: %v", err)
	}
}

func TestRFC2136Writer_AlgorithmAndKeyNormalization(t *testing.T) {
	// "hmac-sha256" with no trailing dot is the user-friendly form per
	// Lego convention; miekg/dns wants it FQDN-style. Ditto for the key
	// name. The writer must normalize both at construction time.
	w, err := buildRFC2136Writer(map[string]string{
		"nameserver":     "ns1.example.com:53",
		"tsig_algorithm": "hmac-sha256",
		"tsig_key":       "auto-config",
		"tsig_secret":    testTSIGSecret,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	rw := w.(*rfc2136Writer)
	if rw.algorithm != "hmac-sha256." {
		t.Errorf("algorithm should be normalized to FQDN form, got %q", rw.algorithm)
	}
	if rw.keyName != "auto-config." {
		t.Errorf("key name should be normalized to FQDN form, got %q", rw.keyName)
	}

	// Already-FQDN inputs should be left alone (idempotent).
	w2, err := buildRFC2136Writer(map[string]string{
		"nameserver":     "ns1.example.com:53",
		"tsig_algorithm": "hmac-sha256.",
		"tsig_key":       "auto-config.",
		"tsig_secret":    testTSIGSecret,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	rw2 := w2.(*rfc2136Writer)
	if rw2.algorithm != "hmac-sha256." || rw2.keyName != "auto-config." {
		t.Errorf("FQDN inputs should be preserved, got algo=%q key=%q", rw2.algorithm, rw2.keyName)
	}
}

func TestRFC2136Writer_WriteCNAME_HappyPath(t *testing.T) {
	var (
		mu              sync.Mutex
		gotUpdate       bool
		updateZone      string
		updateRecord    *dns.CNAME
		soaQueriedZones []string
	)

	srv := startTestServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(req)

		switch req.Opcode {
		case dns.OpcodeQuery:
			q := req.Question[0]
			switch q.Qtype {
			case dns.TypeSOA:
				mu.Lock()
				soaQueriedZones = append(soaQueriedZones, strings.TrimSuffix(q.Name, "."))
				mu.Unlock()
				// Only example.com is authoritative here.
				if q.Name == "example.com." {
					reply.Answer = append(reply.Answer, soaRR("example.com"))
				} else {
					reply.Rcode = dns.RcodeNameError
				}
			case dns.TypeCNAME:
				// No existing CNAME (NOERROR + empty answer).
			}
		case dns.OpcodeUpdate:
			mu.Lock()
			gotUpdate = true
			updateZone = req.Question[0].Name
			for _, rr := range req.Ns {
				if c, ok := rr.(*dns.CNAME); ok {
					updateRecord = c
				}
			}
			mu.Unlock()
		}

		signReply(req, reply)
		_ = w.WriteMsg(reply)
	})
	defer srv.shutdown()

	w := newTestRFC2136Writer(t, srv.addr)

	if err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300); err != nil {
		t.Fatalf("WriteCNAME: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if !gotUpdate {
		t.Fatal("server never received an UPDATE message")
	}
	if updateZone != "example.com." {
		t.Errorf("expected zone example.com., got %q", updateZone)
	}
	if updateRecord == nil {
		t.Fatal("UPDATE did not contain a CNAME RR")
	}
	if updateRecord.Hdr.Name != "*.app.example.com." {
		t.Errorf("CNAME owner = %q, want *.app.example.com.", updateRecord.Hdr.Name)
	}
	if updateRecord.Target != "us-east.proxy.netbird.io." {
		t.Errorf("CNAME target = %q, want us-east.proxy.netbird.io.", updateRecord.Target)
	}
	if updateRecord.Hdr.Ttl != 300 {
		t.Errorf("CNAME TTL = %d, want 300", updateRecord.Hdr.Ttl)
	}
	// Zone discovery should walk longest-first.
	if len(soaQueriedZones) < 2 || soaQueriedZones[0] != "app.example.com" || soaQueriedZones[1] != "example.com" {
		t.Errorf("expected SOA queries longest-first [app.example.com example.com], got %v", soaQueriedZones)
	}
}

func TestRFC2136Writer_WriteCNAME_IdempotentMatch(t *testing.T) {
	var gotUpdate bool

	srv := startTestServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(req)

		switch req.Opcode {
		case dns.OpcodeQuery:
			q := req.Question[0]
			switch q.Qtype {
			case dns.TypeSOA:
				if q.Name == "example.com." {
					reply.Answer = append(reply.Answer, soaRR("example.com"))
				} else {
					reply.Rcode = dns.RcodeNameError
				}
			case dns.TypeCNAME:
				// Existing CNAME points at our intended target — should be a no-op.
				reply.Answer = append(reply.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "us-east.proxy.netbird.io.",
				})
			}
		case dns.OpcodeUpdate:
			gotUpdate = true
		}

		signReply(req, reply)
		_ = w.WriteMsg(reply)
	})
	defer srv.shutdown()

	w := newTestRFC2136Writer(t, srv.addr)
	if err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300); err != nil {
		t.Fatalf("WriteCNAME: %v", err)
	}
	if gotUpdate {
		t.Fatal("idempotent path must not send an UPDATE when target already matches")
	}
}

func TestRFC2136Writer_WriteCNAME_ConflictDifferentTarget(t *testing.T) {
	srv := startTestServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(req)

		if req.Opcode == dns.OpcodeQuery {
			q := req.Question[0]
			switch q.Qtype {
			case dns.TypeSOA:
				if q.Name == "example.com." {
					reply.Answer = append(reply.Answer, soaRR("example.com"))
				} else {
					reply.Rcode = dns.RcodeNameError
				}
			case dns.TypeCNAME:
				// Existing CNAME points somewhere else.
				reply.Answer = append(reply.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "someone-else.example.net.",
				})
			}
		}

		signReply(req, reply)
		_ = w.WriteMsg(reply)
	})
	defer srv.shutdown()

	w := newTestRFC2136Writer(t, srv.addr)
	err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300)
	if !errors.Is(err, ErrRecordExists) {
		t.Fatalf("expected ErrRecordExists, got %v", err)
	}
}

func TestRFC2136Writer_WriteCNAME_ZoneNotFound(t *testing.T) {
	srv := startTestServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(req)
		// Every SOA query — and any other query — gets NXDOMAIN.
		reply.Rcode = dns.RcodeNameError
		signReply(req, reply)
		_ = w.WriteMsg(reply)
	})
	defer srv.shutdown()

	w := newTestRFC2136Writer(t, srv.addr)
	err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300)
	if !errors.Is(err, ErrZoneNotFound) {
		t.Fatalf("expected ErrZoneNotFound, got %v", err)
	}
}

func TestRFC2136Writer_WriteCNAME_AuthFailure(t *testing.T) {
	srv := startTestServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(req)

		if req.Opcode == dns.OpcodeQuery {
			q := req.Question[0]
			switch q.Qtype {
			case dns.TypeSOA:
				if q.Name == "example.com." {
					reply.Answer = append(reply.Answer, soaRR("example.com"))
				} else {
					reply.Rcode = dns.RcodeNameError
				}
			case dns.TypeCNAME:
				// No existing record → write path proceeds to UPDATE.
			}
		} else if req.Opcode == dns.OpcodeUpdate {
			// Refuse the update — server's update-policy doesn't permit
			// this key to write here.
			reply.Rcode = dns.RcodeRefused
		}

		signReply(req, reply)
		_ = w.WriteMsg(reply)
	})
	defer srv.shutdown()

	w := newTestRFC2136Writer(t, srv.addr)
	err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300)
	if !errors.Is(err, ErrInsufficientScope) {
		t.Fatalf("expected ErrInsufficientScope, got %v", err)
	}
}

func TestRFC2136Writer_WriteCNAME_NotAuthIsScope(t *testing.T) {
	// RcodeNotAuth (TSIG validation failed at the server) maps to scope
	// the same way RcodeRefused does.
	srv := startTestServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(req)

		if req.Opcode == dns.OpcodeQuery {
			q := req.Question[0]
			switch q.Qtype {
			case dns.TypeSOA:
				if q.Name == "example.com." {
					reply.Answer = append(reply.Answer, soaRR("example.com"))
				} else {
					reply.Rcode = dns.RcodeNameError
				}
			}
		} else if req.Opcode == dns.OpcodeUpdate {
			reply.Rcode = dns.RcodeNotAuth
		}

		signReply(req, reply)
		_ = w.WriteMsg(reply)
	})
	defer srv.shutdown()

	w := newTestRFC2136Writer(t, srv.addr)
	err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300)
	if !errors.Is(err, ErrInsufficientScope) {
		t.Fatalf("expected ErrInsufficientScope, got %v", err)
	}
}

func TestRFC2136Writer_DeleteCNAME_Idempotent(t *testing.T) {
	var gotUpdate bool
	srv := startTestServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(req)

		switch req.Opcode {
		case dns.OpcodeQuery:
			q := req.Question[0]
			switch q.Qtype {
			case dns.TypeSOA:
				if q.Name == "example.com." {
					reply.Answer = append(reply.Answer, soaRR("example.com"))
				} else {
					reply.Rcode = dns.RcodeNameError
				}
			case dns.TypeCNAME:
				// No record present → delete should be a no-op, no UPDATE sent.
			}
		case dns.OpcodeUpdate:
			gotUpdate = true
		}

		signReply(req, reply)
		_ = w.WriteMsg(reply)
	})
	defer srv.shutdown()

	w := newTestRFC2136Writer(t, srv.addr)
	if err := w.DeleteCNAME(context.Background(), "*.app.example.com"); err != nil {
		t.Fatalf("DeleteCNAME: %v", err)
	}
	if gotUpdate {
		t.Fatal("delete on missing record should not send an UPDATE")
	}
}

func TestRFC2136Writer_DeleteCNAME_HappyPath(t *testing.T) {
	var (
		mu        sync.Mutex
		gotRemove bool
		removeRR  *dns.CNAME
	)

	srv := startTestServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(req)

		switch req.Opcode {
		case dns.OpcodeQuery:
			q := req.Question[0]
			switch q.Qtype {
			case dns.TypeSOA:
				if q.Name == "example.com." {
					reply.Answer = append(reply.Answer, soaRR("example.com"))
				} else {
					reply.Rcode = dns.RcodeNameError
				}
			case dns.TypeCNAME:
				reply.Answer = append(reply.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "us-east.proxy.netbird.io.",
				})
			}
		case dns.OpcodeUpdate:
			mu.Lock()
			gotRemove = true
			for _, rr := range req.Ns {
				if c, ok := rr.(*dns.CNAME); ok {
					removeRR = c
				}
			}
			mu.Unlock()
		}

		signReply(req, reply)
		_ = w.WriteMsg(reply)
	})
	defer srv.shutdown()

	w := newTestRFC2136Writer(t, srv.addr)
	if err := w.DeleteCNAME(context.Background(), "*.app.example.com"); err != nil {
		t.Fatalf("DeleteCNAME: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !gotRemove {
		t.Fatal("expected an UPDATE removing the CNAME")
	}
	if removeRR == nil || removeRR.Hdr.Name != "*.app.example.com." {
		t.Errorf("expected remove RR for *.app.example.com., got %+v", removeRR)
	}
	// Remove() sets the class to NONE per RFC 2136 section 2.5.4.
	if removeRR != nil && removeRR.Hdr.Class != dns.ClassNONE {
		t.Errorf("Remove RR should have class NONE, got %d", removeRR.Hdr.Class)
	}
}

func TestRFC2136Writer_MapDNSRcode(t *testing.T) {
	// Pure-function unit test for the rcode mapping. Cheap and exhaustive.
	cases := []struct {
		name     string
		rcode    int
		wantSent error // sentinel we expect to see, or nil for success
	}{
		{"success", dns.RcodeSuccess, nil},
		{"refused → scope", dns.RcodeRefused, ErrInsufficientScope},
		{"notauth → scope", dns.RcodeNotAuth, ErrInsufficientScope},
		{"servfail → unavailable", dns.RcodeServerFailure, ErrProviderUnavailable},
		{"nxrrset → exists", dns.RcodeNXRrset, ErrRecordExists},
		{"yxrrset → exists", dns.RcodeYXRrset, ErrRecordExists},
		{"yxdomain → exists", dns.RcodeYXDomain, ErrRecordExists},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mapDNSRcode(c.rcode)
			if c.wantSent == nil {
				if got != nil {
					t.Fatalf("rcode %d: want nil, got %v", c.rcode, got)
				}
				return
			}
			if !errors.Is(got, c.wantSent) {
				t.Fatalf("rcode %d: want %v, got %v", c.rcode, c.wantSent, got)
			}
		})
	}

	// Unknown rcodes get a generic error, not nil.
	if got := mapDNSRcode(15); got == nil {
		t.Fatal("unknown rcode should return non-nil error")
	}
}

func TestRFC2136Writer_NetworkErrorIsUnavailable(t *testing.T) {
	// Point the writer at a closed TCP port to force a connect error.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	w := newTestRFC2136Writer(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = w.WriteCNAME(ctx, "*.app.example.com", "us-east.proxy.netbird.io", 300)
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected ErrProviderUnavailable for closed port, got %v", err)
	}
}
