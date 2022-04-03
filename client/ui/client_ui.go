package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "embed"

	"github.com/getlantern/systray"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
	log "github.com/sirupsen/logrus"
	"github.com/skratchdot/open-golang/open"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/widget"
)

const (
	defaulFailTimeout = time.Duration(3 * time.Second)
	fastFailTimeout   = time.Second
)

func main() {
	var daemonAddr string

	if err := checkPIDFile(); err != nil {
		fmt.Println(err)
		return
	}

	defaultDaemonAddr := "unix:///var/run/wiretrustee.sock"
	if runtime.GOOS == "windows" {
		defaultDaemonAddr = "tcp://127.0.0.1:41731"
	}

	flag.StringVar(
		&daemonAddr, "daemon-addr",
		defaultDaemonAddr,
		"Daemon service address to serve CLI requests [unix|tcp]://[path|host:port]")

	flag.Parse()

	a := app.New()
	client := newServiceClient(daemonAddr, a)
	go func() {
		systray.Run(client.onTrayReady, client.onTrayExit)
	}()

	a.Run()
}

//go:embed connected.ico
var iconConnected []byte

//go:embed disconnected.ico
var iconDisconnected []byte

type serviceClient struct {
	ctx       context.Context
	addr      string
	conn      proto.DaemonServiceClient
	mStatus   *systray.MenuItem
	mUp       *systray.MenuItem
	mDown     *systray.MenuItem
	mSettings *systray.MenuItem

	iMngURL     *widget.Entry
	iConfigFile *widget.Entry
	iLogFile    *widget.Entry

	app       fyne.App
	wSettings fyne.Window

	managementURL string
}

func newServiceClient(addr string, a fyne.App) *serviceClient {
	s := &serviceClient{
		ctx:  context.Background(),
		addr: addr,
		app:  a,
	}
	s.wSettings = s.app.NewWindow("Settings")

	s.iMngURL = widget.NewEntry()
	s.iConfigFile = widget.NewEntry()
	s.iConfigFile.Disable()
	s.iLogFile = widget.NewEntry()
	s.iLogFile.Disable()
	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Management URL", Widget: s.iMngURL},
			{Text: "Config File", Widget: s.iConfigFile},
			{Text: "Log File", Widget: s.iLogFile},
		},
		OnSubmit: func() {
			s.wSettings.Hide()

			s.mSettings.Enable()
			// If managementURL changed, we try to re-login with new URL
			if s.managementURL != s.iMngURL.Text {
				s.managementURL = s.iMngURL.Text
				client, err := s.getSrvClient(fastFailTimeout)
				if err != nil {
					log.Errorf("get daemon client: %v", err)
					return
				}

				_, err = client.Login(s.ctx, &proto.LoginRequest{
					ManagementUrl: s.iMngURL.Text,
				})
				if err != nil {
					log.Errorf("login to management URL: %v", err)
					return
				}

				_, err = client.Up(s.ctx, &proto.UpRequest{})
				if err != nil {
					log.Errorf("login to management URL: %v", err)
					return
				}
			}
		},
		OnCancel: func() {
			s.wSettings.Hide()
			s.mSettings.Enable()
		},
	}

	s.wSettings.SetContent(form)
	s.wSettings.SetCloseIntercept(func() {
		s.wSettings.Hide()
		s.mSettings.Enable()
	})
	s.wSettings.Resize(fyne.NewSize(600, 100))

	return s
}

func (s *serviceClient) up() error {
	conn, err := s.getSrvClient(defaulFailTimeout)
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
	conn, err := s.getSrvClient(defaulFailTimeout)
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
	conn, err := s.getSrvClient(defaulFailTimeout)
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

	s.mStatus = systray.AddMenuItem("Disconnected", "Disconnected")
	s.mStatus.Disable()

	systray.AddSeparator()

	s.mUp = systray.AddMenuItem("Connect", "Connect")

	s.mDown = systray.AddMenuItem("Disconnect", "Disconnect")
	s.mDown.Disable()

	mURL := systray.AddMenuItem("Admin Panel", "Wiretrustee Admin Panel")

	systray.AddSeparator()

	s.mSettings = systray.AddMenuItem("Settings", "Settings of the application")

	systray.AddSeparator()

	mQuit := systray.AddMenuItem("Quit", "Quit the client app")

	go func() {
		s.getSrvConfig()
		for {
			s.updateStatus()
			time.Sleep(time.Second * 3)
		}
	}()

	go func() {
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
			case <-s.mSettings.ClickedCh:
				s.iMngURL.SetText(s.managementURL)
				s.mSettings.Disable()
				s.wSettings.Show()
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
			if err != nil {
				log.Errorf("process connection: %v", err)
			}
		}
	}()
}

func (s *serviceClient) onTrayExit() {
	s.app.Quit()
}

// getSrvClient connection to the service.
func (s *serviceClient) getSrvClient(timeout time.Duration) (proto.DaemonServiceClient, error) {
	if s.conn != nil {
		return s.conn, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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

// getSrvConfig from the service to show it in the settings window.
func (s *serviceClient) getSrvConfig() {
	s.managementURL = "https://api.netbird.io:33073"

	conn, err := s.getSrvClient(fastFailTimeout)
	if err != nil {
		log.Errorf("get client: %v", err)
		return
	}

	cfg, err := conn.GetConfig(s.ctx, &proto.GetConfigRequest{})
	if err != nil {
		log.Errorf("get config settings from server: %v", err)
		return
	}

	if cfg.ManagementUrl != "" {
		s.managementURL = cfg.ManagementUrl
	}
	s.iConfigFile.SetText(cfg.ConfigFile)
	s.iLogFile.SetText(cfg.LogFile)
}

// checkPIDFile exists and return error, or write new.
func checkPIDFile() error {
	pidFile := path.Join(os.TempDir(), "wiretrustee-ui.pid")
	if piddata, err := ioutil.ReadFile(pidFile); err == nil {
		if pid, err := strconv.Atoi(string(piddata)); err == nil {
			if process, err := os.FindProcess(pid); err == nil {
				if err := process.Signal(syscall.Signal(0)); err == nil {
					return fmt.Errorf("process already exists: %d", pid)
				}
			}
		}
	}

	return ioutil.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0o664)
}
