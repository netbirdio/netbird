//go:build linux || darwin

package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/shared/relay/auth/hmac"
	"github.com/netbirdio/netbird/shared/relay/client"
)

var (
	hmacTokenStore = &hmac.TokenStore{}
)

func relayTransfer(serverConnURL string, testData []byte, peerPairs int) {
	connsSender := prepareConnsSender(serverConnURL, peerPairs)
	defer func() {
		for i := 0; i < len(connsSender); i++ {
			err := connsSender[i].Close()
			if err != nil {
				log.Errorf("failed to close connection: %s", err)
			}
		}
	}()

	wg := sync.WaitGroup{}
	wg.Add(len(connsSender))
	for _, conn := range connsSender {
		go func(conn net.Conn) {
			defer wg.Done()
			runWriter(conn, testData)
		}(conn)
	}
	wg.Wait()
}

func runWriter(conn net.Conn, testData []byte) {
	si := NewStartInidication(time.Now(), len(testData))
	_, err := conn.Write(si)
	if err != nil {
		log.Errorf("failed to write to channel: %s", err)
		return
	}
	log.Infof("sent start indication")

	pieceSize := 1024
	testDataLen := len(testData)

	for j := 0; j < testDataLen; j += pieceSize {
		end := j + pieceSize
		if end > testDataLen {
			end = testDataLen
		}
		_, writeErr := conn.Write(testData[j:end])
		if writeErr != nil {
			log.Errorf("failed to write to channel: %s", writeErr)
			return
		}
	}
}

func prepareConnsSender(serverConnURL string, peerPairs int) []net.Conn {
	ctx := context.Background()
	clientsSender := make([]*client.Client, peerPairs)
	for i := 0; i < cap(clientsSender); i++ {
		c := client.NewClient(serverConnURL, hmacTokenStore, "sender-"+fmt.Sprint(i), iface.DefaultMTU)
		if err := c.Connect(ctx); err != nil {
			log.Fatalf("failed to connect to server: %s", err)
		}
		clientsSender[i] = c
	}

	connsSender := make([]net.Conn, 0, peerPairs)
	for i := 0; i < len(clientsSender); i++ {
		conn, err := clientsSender[i].OpenConn(ctx, "receiver-"+fmt.Sprint(i))
		if err != nil {
			log.Fatalf("failed to bind channel: %s", err)
		}
		connsSender = append(connsSender, conn)
	}
	return connsSender
}

func relayReceive(serverConnURL string, peerPairs int) []time.Duration {
	connsReceiver := prepareConnsReceiver(serverConnURL, peerPairs)
	defer func() {
		for i := 0; i < len(connsReceiver); i++ {
			if err := connsReceiver[i].Close(); err != nil {
				log.Errorf("failed to close connection: %s", err)
			}
		}
	}()

	durations := make(chan time.Duration, len(connsReceiver))
	wg := sync.WaitGroup{}
	for _, conn := range connsReceiver {
		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			duration := runReader(conn)
			durations <- duration
		}(conn)
	}
	wg.Wait()

	durationsList := make([]time.Duration, 0, len(connsReceiver))
	for d := range durations {
		durationsList = append(durationsList, d)
		if len(durationsList) == len(connsReceiver) {
			close(durations)
		}
	}

	return durationsList
}

func runReader(conn net.Conn) time.Duration {
	buf := make([]byte, 8192)

	n, readErr := conn.Read(buf)
	if readErr != nil {
		log.Errorf("failed to read from channel: %s", readErr)
		return 0
	}

	si := DecodeStartIndication(buf[:n])
	log.Infof("received start indication: %v", si)

	receivedSize, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("failed to read from relay: %s", err)
	}
	now := time.Now()

	rcv := 0
	for receivedSize < si.TransferSize {
		n, readErr = conn.Read(buf)
		if readErr != nil {
			log.Errorf("failed to read from channel: %s", readErr)
			return 0
		}

		receivedSize += n
		rcv += n
	}
	return time.Since(now)
}

func prepareConnsReceiver(serverConnURL string, peerPairs int) []net.Conn {
	clientsReceiver := make([]*client.Client, peerPairs)
	for i := 0; i < cap(clientsReceiver); i++ {
		c := client.NewClient(serverConnURL, hmacTokenStore, "receiver-"+fmt.Sprint(i), iface.DefaultMTU)
		err := c.Connect(context.Background())
		if err != nil {
			log.Fatalf("failed to connect to server: %s", err)
		}
		clientsReceiver[i] = c
	}

	connsReceiver := make([]net.Conn, 0, peerPairs)
	for i := 0; i < len(clientsReceiver); i++ {
		conn, err := clientsReceiver[i].OpenConn(context.Background(), "sender-"+fmt.Sprint(i))
		if err != nil {
			log.Fatalf("failed to bind channel: %s", err)
		}
		connsReceiver = append(connsReceiver, conn)
	}
	return connsReceiver
}
