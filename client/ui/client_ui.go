package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/getlantern/systray"
	log "github.com/sirupsen/logrus"
	"github.com/skratchdot/open-golang/open"
	"github.com/wiretrustee/wiretrustee/client/internal"
	"github.com/wiretrustee/wiretrustee/client/proto"
	"github.com/wiretrustee/wiretrustee/client/ui/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	systray.Run(onReady, nil)
}

// TODO: implementation for SSO Logins
func onReady() {
	wtIcon, err := ioutil.ReadFile("wiretrustee.ico")
	if err != nil {
		log.Warn(err)
	}
	if wtIcon != nil {
		systray.SetTemplateIcon(wtIcon, wtIcon)
	}

	go func() {
		up := systray.AddMenuItem("Up", "Up")
		down := systray.AddMenuItem("Down", "Down")

		mUrl := systray.AddMenuItem("Open UI", "wiretrustee website")
		systray.AddSeparator()

		mQuitOrig := systray.AddMenuItem("Quit", "Quit the whole app")
		go func() {
			<-mQuitOrig.ClickedCh
			fmt.Println("Requesting quit")
			systray.Quit()
			fmt.Println("Finished quitting")
		}()

		for {
			select {
			case <-mUrl.ClickedCh:
				open.Run("https://app.wiretrustee.com")
			case <-up.ClickedCh:
				upCmdExec()
			case <-down.ClickedCh:
				fmt.Println("Clicked down")
			}
		}
	}()
}

func handleUp() {
	// This is where
}

func upCmdExec() {
	log.Println("executing up command..")
	cfg := config.Config()

	ctx := internal.CtxInitState(context.Background())

	conn, err := grpc.DialContext(ctx, cfg.DaemonAddr(),
		grpc.WithTimeout(5*time.Second),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock())
	if err != nil {
		log.Errorf("failed to connect to service CLI interface; %v", err)
		return
	}
	daemonClient := proto.NewDaemonServiceClient(conn)

	status, err := daemonClient.Status(ctx, &proto.StatusRequest{})
	if err != nil {
		log.Errorf("get status: %v", err)
		return
	}

	if status.Status != string(internal.StatusIdle) {
		log.Warnf("already connected")
		return
	}
	_, err = daemonClient.Up(ctx, &proto.UpRequest{})
	if err != nil {
		log.Errorf("Failed to start up client; %v", err)
		return
	}
}
