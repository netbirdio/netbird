package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/netbirdio/netbird/sharedsock"
	log "github.com/sirupsen/logrus"
)

func main() {

	port := 51820
	rawSock, err := sharedsock.Listen(port, sharedsock.NewIncomingSTUNFilter())
	if err != nil {
		panic(err)
	}

	log.Infof("attached to the raw socket on port %d", port)

	ctx, cancel := context.WithCancel(context.Background())
	// read packets
	go func() {
		buf := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				log.Debugf("stopped reading from the shared socket")
				return
			default:
				size, addr, err := rawSock.ReadFrom(buf)
				if err != nil {
					log.Errorf("error while reading packet from the shared socket: %s", err)
					continue
				}
				log.Infof("read a STUN packet of size %d from %s", size, addr.String())
			}
		}
	}()

	// terminate the program on ^C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			log.Infof("received ^C signal, stopping the program")
			cancel()
			err = rawSock.Close()
			if err != nil {
				log.Errorf("failed closing raw socket")
			}
		}
	}()

	<-ctx.Done()
}
