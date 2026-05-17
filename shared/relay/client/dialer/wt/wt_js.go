//go:build js

// Package wt is the browser/WASM WebTransport dialer for the relay client.
//
// WebTransport is the only browser-exposed primitive over HTTP/3 that gives us
// raw bidi-capable QUIC sessions with datagrams. The relay protocol is
// message-framed and small (<= 8 KB) so we use datagrams here, matching the
// raw-QUIC native dialer's semantics (no head-of-line blocking, unreliable).
//
// In production builds the browser performs normal TLS validation against the
// system trust store. Under the `devcert` build tag the server publishes a
// short-lived ECDSA self-signed cert; the WASM client pins its SHA-256 hash
// through `serverCertificateHashes` so the browser will accept it without a
// trusted CA.
package wt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall/js"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/relay"
	relaytls "github.com/netbirdio/netbird/shared/relay/tls"
)

// Network is the protocol identifier reported via Dialer.Protocol.
const Network = "wt"

type Dialer struct{}

func (Dialer) Protocol() string { return Network }

func (Dialer) Dial(ctx context.Context, address, serverName string) (net.Conn, error) {
	wtURL, err := prepareURL(address)
	if err != nil {
		return nil, err
	}

	jsWebTransport := js.Global().Get("WebTransport")
	if !jsWebTransport.Truthy() {
		return nil, errors.New("WebTransport is not supported in this browser")
	}

	opts := map[string]interface{}{}
	if hash := relaytls.DevCertHash(); hash != nil {
		u8 := js.Global().Get("Uint8Array").New(len(hash))
		js.CopyBytesToJS(u8, hash)
		opts["serverCertificateHashes"] = []interface{}{
			map[string]interface{}{"algorithm": "sha-256", "value": u8},
		}
	}

	wt := jsWebTransport.New(wtURL, opts)
	if _, err := awaitPromise(ctx, wt.Get("ready")); err != nil {
		_ = safeCall(wt, "close")
		return nil, fmt.Errorf("WebTransport handshake to %s: %w", wtURL, err)
	}

	log.Debugf("WebTransport session established to %s", wtURL)
	return newConn(wt, address), nil
}

// prepareURL rewrites a rels://host[:port] address into the https URL the
// browser dials. Plain rel:// is not supported — WebTransport requires HTTPS.
func prepareURL(address string) (string, error) {
	parsed, err := url.Parse(address)
	if err != nil {
		return "", fmt.Errorf("parse relay address %q: %w", address, err)
	}
	switch parsed.Scheme {
	case "rels":
		parsed.Scheme = "https"
	case "rel":
		return "", errors.New("WebTransport requires TLS; use rels:// not rel://")
	default:
		return "", fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("missing host in relay address %q", address)
	}
	parsed.Path = relay.WebSocketURLPath
	return parsed.String(), nil
}

// awaitPromise bridges a JS Promise to a Go return. It respects ctx
// cancellation and releases its js.Func callbacks on the resolve/reject path.
func awaitPromise(ctx context.Context, p js.Value) (js.Value, error) {
	type res struct {
		val js.Value
		err error
	}
	ch := make(chan res, 1)
	var thenFn, catchFn js.Func
	release := func() {
		thenFn.Release()
		catchFn.Release()
	}
	thenFn = js.FuncOf(func(_ js.Value, args []js.Value) interface{} {
		var v js.Value
		if len(args) > 0 {
			v = args[0]
		}
		select {
		case ch <- res{val: v}:
		default:
		}
		return nil
	})
	catchFn = js.FuncOf(func(_ js.Value, args []js.Value) interface{} {
		msg := "promise rejected"
		if len(args) > 0 && args[0].Truthy() {
			msg = args[0].Call("toString").String()
		}
		select {
		case ch <- res{err: errors.New(msg)}:
		default:
		}
		return nil
	})
	p.Call("then", thenFn).Call("catch", catchFn)

	select {
	case r := <-ch:
		release()
		return r.val, r.err
	case <-ctx.Done():
		release()
		return js.Value{}, ctx.Err()
	}
}

// safeCall invokes a js method and swallows panics from a dead JS object.
func safeCall(v js.Value, method string, args ...interface{}) (out js.Value) {
	defer func() { _ = recover() }()
	out = v.Call(method, args...)
	return
}
