package quic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/server/listener"
)

type Listener struct {
	address    string
	onAcceptFn func(conn net.Conn)

	listener *quic.Listener
	quit     chan struct{}
	wg       sync.WaitGroup
}

func NewListener(address string) listener.Listener {
	return &Listener{
		address: address,
	}
}

func (l *Listener) Listen(onAcceptFn func(conn net.Conn)) error {
	ql, err := quic.ListenAddr(l.address, generateTLSConfig(), &quic.Config{
		EnableDatagrams: true,
	})
	if err != nil {
		return err
	}
	l.listener = ql
	l.quit = make(chan struct{})

	log.Infof("quic server is listening on address: %s", l.address)
	l.wg.Add(1)
	go l.acceptLoop(onAcceptFn)

	<-l.quit
	return nil
}

func (l *Listener) Close() error {
	close(l.quit)
	err := l.listener.Close()
	l.wg.Wait()
	return err
}

func (l *Listener) acceptLoop(acceptFn func(conn net.Conn)) {
	defer l.wg.Done()

	for {
		qConn, err := l.listener.Accept(context.Background())
		if err != nil {
			select {
			case <-l.quit:
				return
			default:
				log.Errorf("failed to accept connection: %s", err)
				continue
			}
		}

		log.Infof("new connection from: %s", qConn.RemoteAddr())

		stream, err := qConn.AcceptStream(context.Background())
		if err != nil {
			log.Errorf("failed to open stream: %s", err)
			continue
		}

		conn := NewConn(stream, qConn)

		go acceptFn(conn)
	}
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}
