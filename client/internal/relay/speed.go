package relay

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	bufferSize = 800
	testFile   = "/tmp/1MB"
)

type Speed struct {
}

func NewSpeed() *Speed {
	return &Speed{}
}

func (s *Speed) ReceiveFileFromAddr(remoteAddr net.Addr) error {
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		log.Errorf("failed to lisen: %s", err.Error())
		return err
	}
	defer pc.Close()

	log.Debugf("--- sending initial message to: %s", remoteAddr.String())
	_, err = pc.WriteTo([]byte("hey, I am the receiver"), remoteAddr)
	if err != nil {
		log.Errorf("failed to send initial msg: %s", err.Error())
		return err
	}

	return s.receiveFile(pc)
}

func (s *Speed) ReceiveFileFromPC(pc net.PacketConn) error {
	return s.receiveFile(pc)
}

func (s *Speed) receiveFile(pc net.PacketConn) error {
	log.Debugf("--- start to receive file...")
	file, err := os.OpenFile(fmt.Sprintf("%s.cp", testFile), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Errorf("failed to open file: %s", err.Error())
		return err
	}
	_ = file.Truncate(0)
	defer file.Close()

	buffer := make([]byte, bufferSize)
	for {
		n, addr, err := pc.ReadFrom(buffer)
		if err != nil {
			log.Errorf("failed to read from connection: %s", err.Error())
			return err
		}

		n, err = file.Write(buffer[:n])
		if err != nil {
			log.Errorf("failed to write to file: %s", err.Error())
			return err
		}

		_, err = pc.WriteTo([]byte("ack"), addr)
		if err != nil {
			log.Errorf("failed to send ack: %s", err.Error())
		}

		log.Debugf("received %d bytes from %s", n, addr)
	}
}

func (s *Speed) SendFileToPC(relayConn net.PacketConn) error {
	buf := make([]byte, bufferSize)
	log.Debugf("--- wait for initial message")
	n, rAddr, err := relayConn.ReadFrom(buf)
	if err != nil {
		log.Errorf("failed to read from connection: %s", err.Error())
		return err
	}
	log.Errorf("received initial msg %d bytes (%s), addr %s", n, string(buf[:n]), rAddr.String())
	return s.sendFile(relayConn, rAddr)
}

func (s *Speed) SendFileToAddr(addr net.Addr) error {
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		log.Errorf("failed to lisen: %s", err.Error())
		return err
	}
	defer pc.Close()

	return s.sendFile(pc, addr)
}

func (s *Speed) sendFile(conn net.PacketConn, rAddr net.Addr) error {
	log.Debugf("--- start to send file...")
	file, err := os.Open(testFile)
	if err != nil {
		// Handle error
		return nil
	}
	defer file.Close()

	buf := make([]byte, bufferSize)
	start := time.Now()
	sent := 0

	for {
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		n, err = conn.WriteTo(buf[:n], rAddr)
		if err != nil {
			log.Errorf("failed to write to connection: %s", err.Error())
			return err
		}
		sent += n
		log.Debugf("sent %d bytes, (%d) to %s", n, sent, rAddr.String())

		// wait for ack
		_, _, err = conn.ReadFrom(make([]byte, bufferSize))
		if err != nil {
			log.Errorf("failed to read from connection: %s", err.Error())
			return err
		}
	}
	elapsed := time.Since(start)
	log.Infof("sent %d bytes, troughtput: %f MB/s", sent, float64(sent)/1024/1024/elapsed.Seconds())
	return nil
}
