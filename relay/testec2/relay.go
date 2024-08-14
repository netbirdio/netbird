package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/auth/hmac"
	"github.com/netbirdio/netbird/relay/client"
)

var (
	hmacTokenStore = &hmac.TokenStore{}
)

func relayTransfer(serverConnURL string, testData []byte, peerPairs int) {
	ctx := context.Background()

	clientsSender := make([]*client.Client, peerPairs)
	for i := 0; i < cap(clientsSender); i++ {
		c := client.NewClient(ctx, serverConnURL, hmacTokenStore, "sender-"+fmt.Sprint(i))
		if err := c.Connect(); err != nil {
			log.Fatalf("failed to connect to server: %s", err)
		}
		clientsSender[i] = c
	}

	connsSender := make([]net.Conn, 0, peerPairs)
	for i := 0; i < len(clientsSender); i++ {
		conn, err := clientsSender[i].OpenConn("receiver-" + fmt.Sprint(i))
		if err != nil {
			log.Fatalf("failed to bind channel: %s", err)
		}
		connsSender = append(connsSender, conn)
	}

	defer func() {
		for i := 0; i < len(connsSender); i++ {
			err := connsSender[i].Close()
			if err != nil {
				log.Errorf("failed to close connection: %s", err)
			}
		}
	}()

	wg := sync.WaitGroup{}
	var writeErr error
	for i, conn := range connsSender {
		wg.Add(1)
		go func(i int, conn net.Conn) {
			defer wg.Done()

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
				_, writeErr = conn.Write(testData[j:end])
				if writeErr != nil {
					log.Errorf("failed to write to channel: %s", writeErr)
					return
				}
			}
		}(i, conn)
	}
	wg.Wait()
}

func relayReceive(serverConnURL string, peerPairs int) []time.Duration {
	clientsReceiver := make([]*client.Client, peerPairs)
	for i := 0; i < cap(clientsReceiver); i++ {
		c := client.NewClient(context.Background(), serverConnURL, hmacTokenStore, "receiver-"+fmt.Sprint(i))
		err := c.Connect()
		if err != nil {
			log.Fatalf("failed to connect to server: %s", err)
		}
		clientsReceiver[i] = c
	}

	connsReceiver := make([]net.Conn, 0, peerPairs)
	for i := 0; i < len(clientsReceiver); i++ {
		conn, err := clientsReceiver[i].OpenConn("sender-" + fmt.Sprint(i))
		if err != nil {
			log.Fatalf("failed to bind channel: %s", err)
		}
		connsReceiver = append(connsReceiver, conn)
	}

	defer func() {
		for i := 0; i < len(connsReceiver); i++ {
			if err := connsReceiver[i].Close(); err != nil {
				log.Errorf("failed to close connection: %s", err)
			}
		}
	}()

	durations := make(chan time.Duration, len(connsReceiver))
	wg := sync.WaitGroup{}
	for i, conn := range connsReceiver {
		wg.Add(1)
		go func(i int, conn net.Conn) {
			defer wg.Done()
			buf := make([]byte, 8192)

			n, readErr := conn.Read(buf)
			if readErr != nil {
				log.Errorf("failed to read from channel: %s", readErr)
				return
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
					return
				}

				receivedSize += n
				rcv += n
			}
			durations <- time.Since(now)
		}(i, conn)
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
