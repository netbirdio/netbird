//go:build js

package rdp

import (
	"crypto/tls"
	"encoding/asn1"
	"io"
	"syscall/js"

	log "github.com/sirupsen/logrus"
)

func (p *RDCleanPathProxy) processRDCleanPathPDU(conn *proxyConnection, pdu RDCleanPathPDU) {
	log.Infof("Processing RDCleanPath PDU: Version=%d, Destination=%s", pdu.Version, pdu.Destination)

	if pdu.Version != RDCleanPathVersion {
		p.sendRDCleanPathError(conn, "Unsupported version")
		return
	}

	destination := conn.destination
	if pdu.Destination != "" {
		destination = pdu.Destination
	}

	rdpConn, err := p.nbClient.Dial(conn.ctx, "tcp", destination)
	if err != nil {
		log.Errorf("Failed to connect to %s: %v", destination, err)
		p.sendRDCleanPathError(conn, "Connection failed")
		p.cleanupConnection(conn)
		return
	}
	conn.rdpConn = rdpConn

	// RDP always starts with X.224 negotiation, then determines if TLS is needed
	// Modern RDP (since Windows Vista/2008) typically requires TLS
	// The X.224 Connection Confirm response will indicate if TLS is required
	// For now, we'll attempt TLS for all connections as it's the modern default
	p.setupTLSConnection(conn, pdu)
}

func (p *RDCleanPathProxy) setupTLSConnection(conn *proxyConnection, pdu RDCleanPathPDU) {
	var x224Response []byte
	if len(pdu.X224ConnectionPDU) > 0 {
		log.Debugf("Forwarding X.224 Connection Request (%d bytes)", len(pdu.X224ConnectionPDU))
		_, err := conn.rdpConn.Write(pdu.X224ConnectionPDU)
		if err != nil {
			log.Errorf("Failed to write X.224 PDU: %v", err)
			p.sendRDCleanPathError(conn, "Failed to forward X.224")
			return
		}

		response := make([]byte, 1024)
		n, err := conn.rdpConn.Read(response)
		if err != nil {
			log.Errorf("Failed to read X.224 response: %v", err)
			p.sendRDCleanPathError(conn, "Failed to read X.224 response")
			return
		}
		x224Response = response[:n]
		log.Debugf("Received X.224 Connection Confirm (%d bytes)", n)
	}

	tlsConfig := p.getTLSConfigWithValidation(conn)

	tlsConn := tls.Client(conn.rdpConn, tlsConfig)
	conn.tlsConn = tlsConn

	if err := tlsConn.Handshake(); err != nil {
		log.Errorf("TLS handshake failed: %v", err)
		p.sendRDCleanPathError(conn, "TLS handshake failed")
		return
	}

	log.Info("TLS handshake successful")

	// Certificate validation happens during handshake via VerifyConnection callback
	var certChain [][]byte
	connState := tlsConn.ConnectionState()
	if len(connState.PeerCertificates) > 0 {
		for _, cert := range connState.PeerCertificates {
			certChain = append(certChain, cert.Raw)
		}
		log.Debugf("Extracted %d certificates from TLS connection", len(certChain))
	}

	responsePDU := RDCleanPathPDU{
		Version:         RDCleanPathVersion,
		ServerAddr:      conn.destination,
		ServerCertChain: certChain,
	}

	if len(x224Response) > 0 {
		responsePDU.X224ConnectionPDU = x224Response
	}

	p.sendRDCleanPathPDU(conn, responsePDU)

	log.Debug("Starting TLS forwarding")
	go p.forwardConnToWS(conn, conn.tlsConn, "TLS")
	go p.forwardWSToConn(conn, conn.tlsConn, "TLS")

	<-conn.ctx.Done()
	log.Debug("TLS connection context done, cleaning up")
	p.cleanupConnection(conn)
}

func (p *RDCleanPathProxy) setupPlainConnection(conn *proxyConnection, pdu RDCleanPathPDU) {
	if len(pdu.X224ConnectionPDU) > 0 {
		log.Debugf("Forwarding X.224 Connection Request (%d bytes)", len(pdu.X224ConnectionPDU))
		_, err := conn.rdpConn.Write(pdu.X224ConnectionPDU)
		if err != nil {
			log.Errorf("Failed to write X.224 PDU: %v", err)
			p.sendRDCleanPathError(conn, "Failed to forward X.224")
			return
		}

		response := make([]byte, 1024)
		n, err := conn.rdpConn.Read(response)
		if err != nil {
			log.Errorf("Failed to read X.224 response: %v", err)
			p.sendRDCleanPathError(conn, "Failed to read X.224 response")
			return
		}

		responsePDU := RDCleanPathPDU{
			Version:           RDCleanPathVersion,
			X224ConnectionPDU: response[:n],
			ServerAddr:        conn.destination,
		}

		p.sendRDCleanPathPDU(conn, responsePDU)
	} else {
		responsePDU := RDCleanPathPDU{
			Version:    RDCleanPathVersion,
			ServerAddr: conn.destination,
		}
		p.sendRDCleanPathPDU(conn, responsePDU)
	}

	go p.forwardConnToWS(conn, conn.rdpConn, "TCP")
	go p.forwardWSToConn(conn, conn.rdpConn, "TCP")

	<-conn.ctx.Done()
	log.Debug("TCP connection context done, cleaning up")
	p.cleanupConnection(conn)
}

func (p *RDCleanPathProxy) sendRDCleanPathPDU(conn *proxyConnection, pdu RDCleanPathPDU) {
	data, err := asn1.Marshal(pdu)
	if err != nil {
		log.Errorf("Failed to marshal RDCleanPath PDU: %v", err)
		return
	}

	log.Debugf("Sending RDCleanPath PDU response (%d bytes)", len(data))
	p.sendToWebSocket(conn, data)
}

func (p *RDCleanPathProxy) sendRDCleanPathError(conn *proxyConnection, errorMsg string) {
	pdu := RDCleanPathPDU{
		Version: RDCleanPathVersion,
		Error:   []byte(errorMsg),
	}

	data, err := asn1.Marshal(pdu)
	if err != nil {
		log.Errorf("Failed to marshal error PDU: %v", err)
		return
	}

	p.sendToWebSocket(conn, data)
}

func (p *RDCleanPathProxy) readWebSocketMessage(conn *proxyConnection) ([]byte, error) {
	msgChan := make(chan []byte)
	errChan := make(chan error)

	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) < 1 {
			errChan <- io.EOF
			return nil
		}

		data := args[0]
		if data.InstanceOf(js.Global().Get("Uint8Array")) {
			length := data.Get("length").Int()
			bytes := make([]byte, length)
			js.CopyBytesToGo(bytes, data)
			msgChan <- bytes
		}
		return nil
	})
	defer handler.Release()

	conn.wsHandlers.Set("onceGoMessage", handler)

	select {
	case msg := <-msgChan:
		return msg, nil
	case err := <-errChan:
		return nil, err
	case <-conn.ctx.Done():
		return nil, conn.ctx.Err()
	}
}

func (p *RDCleanPathProxy) forwardWSToConn(conn *proxyConnection, dst io.Writer, connType string) {
	for {
		if conn.ctx.Err() != nil {
			return
		}

		msg, err := p.readWebSocketMessage(conn)
		if err != nil {
			if err != io.EOF {
				log.Errorf("Failed to read from WebSocket: %v", err)
			}
			return
		}

		_, err = dst.Write(msg)
		if err != nil {
			log.Errorf("Failed to write to %s: %v", connType, err)
			return
		}
	}
}

func (p *RDCleanPathProxy) forwardConnToWS(conn *proxyConnection, src io.Reader, connType string) {
	buffer := make([]byte, 32*1024)

	for {
		if conn.ctx.Err() != nil {
			return
		}

		n, err := src.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Errorf("Failed to read from %s: %v", connType, err)
			}
			return
		}

		if n > 0 {
			p.sendToWebSocket(conn, buffer[:n])
		}
	}
}
