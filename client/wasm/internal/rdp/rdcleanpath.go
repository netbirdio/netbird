//go:build js

package rdp

import (
	"context"
	"crypto/tls"
	"encoding/asn1"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall/js"

	log "github.com/sirupsen/logrus"
)

const (
	RDCleanPathVersion     = 3390
	RDCleanPathProxyHost   = "rdcleanpath.proxy.local"
	RDCleanPathProxyScheme = "ws"
)

type RDCleanPathPDU struct {
	Version           int64    `asn1:"tag:0,explicit"`
	Error             []byte   `asn1:"tag:1,explicit,optional"`
	Destination       string   `asn1:"utf8,tag:2,explicit,optional"`
	ProxyAuth         string   `asn1:"utf8,tag:3,explicit,optional"`
	ServerAuth        string   `asn1:"utf8,tag:4,explicit,optional"`
	PreconnectionBlob string   `asn1:"utf8,tag:5,explicit,optional"`
	X224ConnectionPDU []byte   `asn1:"tag:6,explicit,optional"`
	ServerCertChain   [][]byte `asn1:"tag:7,explicit,optional"`
	ServerAddr        string   `asn1:"utf8,tag:9,explicit,optional"`
}

type RDCleanPathProxy struct {
	nbClient interface {
		Dial(ctx context.Context, network, address string) (net.Conn, error)
	}
	activeConnections map[string]*proxyConnection
	destinations      map[string]string
	mu                sync.Mutex
}

type proxyConnection struct {
	id          string
	destination string
	rdpConn     net.Conn
	tlsConn     *tls.Conn
	wsHandlers  js.Value
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewRDCleanPathProxy creates a new RDCleanPath proxy
func NewRDCleanPathProxy(client interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}) *RDCleanPathProxy {
	return &RDCleanPathProxy{
		nbClient:          client,
		activeConnections: make(map[string]*proxyConnection),
	}
}

// CreateProxy creates a new proxy endpoint for the given destination
func (p *RDCleanPathProxy) CreateProxy(hostname, port string) js.Value {
	destination := fmt.Sprintf("%s:%s", hostname, port)

	return js.Global().Get("Promise").New(js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve := args[0]

		go func() {
			proxyID := fmt.Sprintf("proxy_%d", len(p.activeConnections))

			p.mu.Lock()
			if p.destinations == nil {
				p.destinations = make(map[string]string)
			}
			p.destinations[proxyID] = destination
			p.mu.Unlock()

			proxyURL := fmt.Sprintf("%s://%s/%s", RDCleanPathProxyScheme, RDCleanPathProxyHost, proxyID)

			// Register the WebSocket handler for this specific proxy
			js.Global().Set(fmt.Sprintf("handleRDCleanPathWebSocket_%s", proxyID), js.FuncOf(func(_ js.Value, args []js.Value) any {
				if len(args) < 1 {
					return js.ValueOf("error: requires WebSocket argument")
				}

				ws := args[0]
				p.HandleWebSocketConnection(ws, proxyID)
				return nil
			}))

			log.Infof("Created RDCleanPath proxy endpoint: %s for destination: %s", proxyURL, destination)
			resolve.Invoke(proxyURL)
		}()

		return nil
	}))
}

// HandleWebSocketConnection handles incoming WebSocket connections from IronRDP
func (p *RDCleanPathProxy) HandleWebSocketConnection(ws js.Value, proxyID string) {
	p.mu.Lock()
	destination := p.destinations[proxyID]
	p.mu.Unlock()

	if destination == "" {
		log.Errorf("No destination found for proxy ID: %s", proxyID)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Don't defer cancel here - it will be called by cleanupConnection

	conn := &proxyConnection{
		id:          proxyID,
		destination: destination,
		wsHandlers:  ws,
		ctx:         ctx,
		cancel:      cancel,
	}

	p.mu.Lock()
	p.activeConnections[proxyID] = conn
	p.mu.Unlock()

	p.setupWebSocketHandlers(ws, conn)

	log.Infof("RDCleanPath proxy WebSocket connection established for %s", proxyID)
}

func (p *RDCleanPathProxy) setupWebSocketHandlers(ws js.Value, conn *proxyConnection) {
	ws.Set("onGoMessage", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return nil
		}

		data := args[0]
		go p.handleWebSocketMessage(conn, data)
		return nil
	}))

	ws.Set("onGoClose", js.FuncOf(func(_ js.Value, args []js.Value) any {
		log.Debug("WebSocket closed by JavaScript")
		conn.cancel()
		return nil
	}))
}

func (p *RDCleanPathProxy) handleWebSocketMessage(conn *proxyConnection, data js.Value) {
	if !data.InstanceOf(js.Global().Get("Uint8Array")) {
		return
	}

	length := data.Get("length").Int()
	bytes := make([]byte, length)
	js.CopyBytesToGo(bytes, data)

	if conn.rdpConn != nil || conn.tlsConn != nil {
		p.forwardToRDP(conn, bytes)
		return
	}

	var pdu RDCleanPathPDU
	_, err := asn1.Unmarshal(bytes, &pdu)
	if err != nil {
		log.Warnf("Failed to parse RDCleanPath PDU: %v", err)
		n := len(bytes)
		if n > 20 {
			n = 20
		}
		log.Warnf("First %d bytes: %x", n, bytes[:n])

		if len(bytes) > 0 && bytes[0] == 0x03 {
			log.Debug("Received raw RDP packet instead of RDCleanPath PDU")
			go p.handleDirectRDP(conn, bytes)
			return
		}
		return
	}

	go p.processRDCleanPathPDU(conn, pdu)
}

func (p *RDCleanPathProxy) forwardToRDP(conn *proxyConnection, bytes []byte) {
	var writer io.Writer
	var connType string

	if conn.tlsConn != nil {
		writer = conn.tlsConn
		connType = "TLS"
	} else if conn.rdpConn != nil {
		writer = conn.rdpConn
		connType = "TCP"
	} else {
		log.Error("No RDP connection available")
		return
	}

	if _, err := writer.Write(bytes); err != nil {
		log.Errorf("Failed to write to %s: %v", connType, err)
	}
}

func (p *RDCleanPathProxy) handleDirectRDP(conn *proxyConnection, firstPacket []byte) {
	defer p.cleanupConnection(conn)

	destination := conn.destination
	log.Infof("Direct RDP mode: Connecting to %s via NetBird", destination)

	rdpConn, err := p.nbClient.Dial(conn.ctx, "tcp", destination)
	if err != nil {
		log.Errorf("Failed to connect to %s: %v", destination, err)
		return
	}
	conn.rdpConn = rdpConn

	_, err = rdpConn.Write(firstPacket)
	if err != nil {
		log.Errorf("Failed to write first packet: %v", err)
		return
	}

	response := make([]byte, 1024)
	n, err := rdpConn.Read(response)
	if err != nil {
		log.Errorf("Failed to read X.224 response: %v", err)
		return
	}

	p.sendToWebSocket(conn, response[:n])

	go p.forwardWSToConn(conn, conn.rdpConn, "TCP")
	go p.forwardConnToWS(conn, conn.rdpConn, "TCP")
}

func (p *RDCleanPathProxy) cleanupConnection(conn *proxyConnection) {
	log.Debugf("Cleaning up connection %s", conn.id)
	conn.cancel()
	if conn.tlsConn != nil {
		log.Debug("Closing TLS connection")
		if err := conn.tlsConn.Close(); err != nil {
			log.Debugf("Error closing TLS connection: %v", err)
		}
		conn.tlsConn = nil
	}
	if conn.rdpConn != nil {
		log.Debug("Closing TCP connection")
		if err := conn.rdpConn.Close(); err != nil {
			log.Debugf("Error closing TCP connection: %v", err)
		}
		conn.rdpConn = nil
	}
	p.mu.Lock()
	delete(p.activeConnections, conn.id)
	p.mu.Unlock()
}

func (p *RDCleanPathProxy) sendToWebSocket(conn *proxyConnection, data []byte) {
	if conn.wsHandlers.Get("receiveFromGo").Truthy() {
		uint8Array := js.Global().Get("Uint8Array").New(len(data))
		js.CopyBytesToJS(uint8Array, data)
		conn.wsHandlers.Call("receiveFromGo", uint8Array.Get("buffer"))
	} else if conn.wsHandlers.Get("send").Truthy() {
		uint8Array := js.Global().Get("Uint8Array").New(len(data))
		js.CopyBytesToJS(uint8Array, data)
		conn.wsHandlers.Call("send", uint8Array.Get("buffer"))
	}
}
