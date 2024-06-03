package quic

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
)

func Dial(address string) (net.Conn, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	qConn, err := quic.DialAddr(context.Background(), address, tlsConf, &quic.Config{
		EnableDatagrams: true,
	})
	if err != nil {
		log.Errorf("dial quic address %s failed: %s", address, err)
		return nil, err
	}

	stream, err := qConn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}

	conn := NewConn(stream, qConn)
	return conn, nil
}
