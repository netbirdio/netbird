package main

import (
	"context"
	"flag"
	"fmt"
	"runtime"
	"strings"
	"time"

	_ "embed"

	"github.com/getlantern/systray"
	log "github.com/sirupsen/logrus"
	"github.com/skratchdot/open-golang/open"
	"github.com/wiretrustee/wiretrustee/client/internal"
	"github.com/wiretrustee/wiretrustee/client/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	var daemonAddr string

	defaultDaemonAddr := "unix:///var/run/wiretrustee.sock"
	if runtime.GOOS == "windows" {
		defaultDaemonAddr = "tcp://127.0.0.1:41731"
	}

	flag.StringVar(
		&daemonAddr, "daemon-addr",
		defaultDaemonAddr,
		"Daemon service address to serve CLI requests [unix|tcp]://[path|host:port]")

	flag.Parse()

	client := newServiceClient(daemonAddr)
	systray.Run(client.onTrayReady, client.onTrayExit)
}

//go:embed connected.ico
var iconConnected []byte

//go:embed disconnected.ico
var iconDisconnected []byte

type serviceClient struct {
	ctx     context.Context
	addr    string
	conn    proto.DaemonServiceClient
	mStatus *systray.MenuItem
	mUp     *systray.MenuItem
	mDown   *systray.MenuItem
}

func newServiceClient(addr string) *serviceClient {
	s := &serviceClient{
		ctx:  context.Background(),
		addr: addr,
	}
	return s
}

func (s *serviceClient) up() error {
	conn, err := s.client()
	if err != nil {
		log.Errorf("get client: %v", err)
		return err
	}

	status, err := conn.Status(s.ctx, &proto.StatusRequest{})
	if err != nil {
		log.Errorf("get service status: %v", err)
		return err
	}

	if status.Status != string(internal.StatusIdle) {
		log.Warnf("already connected")
		return nil
	}

	if _, err := s.conn.Up(s.ctx, &proto.UpRequest{}); err != nil {
		log.Errorf("up service: %v", err)
		return err
	}

	return nil
}

func (s *serviceClient) down() error {
	conn, err := s.client()
	if err != nil {
		log.Errorf("get client: %v", err)
		return err
	}

	status, err := conn.Status(s.ctx, &proto.StatusRequest{})
	if err != nil {
		log.Errorf("get service status: %v", err)
		return err
	}

	if status.Status != string(internal.StatusConnected) {
		log.Warnf("already down")
		return nil
	}

	if _, err := s.conn.Down(s.ctx, &proto.DownRequest{}); err != nil {
		log.Errorf("down service: %v", err)
		return err
	}

	return nil
}

func (s *serviceClient) updateStatus() {
	conn, err := s.client()
	if err != nil {
		log.Errorf("get client: %v", err)
		return
	}

	status, err := conn.Status(s.ctx, &proto.StatusRequest{})
	if err != nil {
		log.Errorf("get service status: %v", err)
		return
	}

	if status.Status == string(internal.StatusConnected) {
		systray.SetTemplateIcon(iconConnected, iconConnected)
		s.mStatus.SetTitle("Connected")
		s.mUp.Disable()
		s.mDown.Enable()
	} else {
		systray.SetTemplateIcon(iconDisconnected, iconDisconnected)
		s.mStatus.SetTitle("Disconnected")
		s.mDown.Disable()
		s.mUp.Enable()
	}
}

func (s *serviceClient) onTrayReady() {
	systray.SetTemplateIcon(iconDisconnected, iconDisconnected)
	go func() {
		s.mStatus = systray.AddMenuItem("Disconnected", "Disconnected")
		s.mStatus.Disable()

		systray.AddSeparator()

		s.mUp = systray.AddMenuItem("Up", "Up")

		s.mDown = systray.AddMenuItem("Down", "Down")
		s.mDown.Disable()

		mURL := systray.AddMenuItem("Open UI", "wiretrustee website")

		systray.AddSeparator()

		mQuit := systray.AddMenuItem("Quit", "Quit the whole app")

		s.updateStatus()

		ticker := time.NewTicker(time.Second * 3)
		defer ticker.Stop()

		var err error
		for {
			select {
			case <-mURL.ClickedCh:
				err = open.Run("https://app.wiretrustee.com")
			case <-s.mUp.ClickedCh:
				s.mUp.Disable()
				if err = s.up(); err != nil {
					s.mUp.Enable()
				}
			case <-s.mDown.ClickedCh:
				s.mDown.Disable()
				if err = s.down(); err != nil {
					s.mDown.Enable()
				}
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			case <-ticker.C:
				s.updateStatus()
			}
			if err != nil {
				log.Errorf("process connection: %v", err)
			}
		}
	}()
}

func (s *serviceClient) onTrayExit() {}

func (s *serviceClient) client() (proto.DaemonServiceClient, error) {
	if s.conn != nil {
		return s.conn, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		strings.TrimPrefix(s.addr, "tcp://"),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("dial service: %w", err)
	}

	s.conn = proto.NewDaemonServiceClient(conn)
	return s.conn, nil
}
