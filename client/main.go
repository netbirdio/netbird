package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/netbirdio/netbird/iface/bind"
)

func main() {

	udp, err := net.ListenUDP("udp4", nil)
	if err != nil {
		panic(err)
	}
	muxDefault := bind.NewUniversalUDPMuxDefault(bind.UniversalUDPMuxParams{UDPConn: udp, XORMappedAddrCacheTTL: 25 * time.Second})

	go func() {
		muxDefault.ReadFromConn(context.TODO())
	}()

	addr, err := net.ResolveUDPAddr("udp4", "18.198.11.240:5555")
	if err != nil {
		panic(err)
	}
	for i := 0; i < 2; i++ {
		go func() {
			millis := rand.Intn(400) + 50
			time.Sleep(time.Duration(millis) * time.Millisecond)

			for {
				a, err := muxDefault.GetXORMappedAddr(addr, 3*time.Second)
				if err != nil {
					//fmt.Println(time.Now())
					fmt.Println(time.Now().String() + ": " + err.Error())
					continue
				}
				//fmt.Println(time.Now())
				fmt.Println(a)
				/*millis = rand.Intn(1000-300) + 300
				time.Sleep(time.Duration(millis) * time.Millisecond)*/
			}
		}()
	}

	select {}
}
