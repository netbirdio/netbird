package main

import (
	"context"
	"github.com/netbirdio/netbird/sharedsock"
	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
)

func main() {
	rawSock, err := sharedsock.Listen(51820, sharedsock.NewIncomingSTUNFilter())
	if err != nil {
		panic(err)
	}

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
		}
	}()

	<-ctx.Done()
}
