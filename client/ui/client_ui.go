package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	"github.com/netbirdio/netbird/util"
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
	"github.com/netbirdio/netbird/client/internal/oauth"
	"github.com/netbirdio/netbird/client/proto"
	log "github.com/sirupsen/logrus"
	"github.com/skratchdot/open-golang/open"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	var daemonAddr string
	err := util.InitLog("debug", "console")
	if err != nil {
		log.Errorf("failed initializing log %v", err)
	}

	if err = checkPIDFile(); err != nil {
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

// WithBackOff execute function in backoff cycle.
func WithBackOff(bf func() error) error {
	return backoff.RetryNotify(bf, CLIBackOffSettings, func(err error, duration time.Duration) {
		log.Warnf("retrying Login to the Management service in %v due to error %v", duration, err)
	})
}

// CLIBackOffSettings is default backoff settings for CLI commands.
var CLIBackOffSettings = &backoff.ExponentialBackOff{
	InitialInterval:     time.Second,
	RandomizationFactor: backoff.DefaultRandomizationFactor,
	Multiplier:          backoff.DefaultMultiplier,
	MaxInterval:         10 * time.Second,
	MaxElapsedTime:      30 * time.Second,
	Stop:                backoff.Stop,
	Clock:               backoff.SystemClock,
}

func (s *serviceClient) login() error {
	var (
		audience      string
		clientID      string
		domain        string
		managementURL string
	)

	audience = os.Getenv("AUDIENCE")
	if audience == "" {
		log.Errorf("AUDIENCE variable is not exported")
	}
	clientID = os.Getenv("CLIENT_ID")
	if clientID == "" {
		log.Errorf("CLIENT_ID variable is not exported")
	}
	domain = os.Getenv("DOMAIN")
	if domain == "" {
		log.Errorf("DOMAIN variable is not exported")
	}
	managementURL = os.Getenv("MANAGEMENT_URL")
	if managementURL == "" {
		log.Errorf("MANAGEMENT_URL variable is not exported")
	}

	auth0Client := oauth.NewAuth0DeviceFlow(audience, clientID, domain)

	authInfo, err := auth0Client.RequestDeviceCode(context.TODO())
	if err != nil {
		log.Error(err)
	}

	err = open.Run(authInfo.VerificationURIComplete)
	if err != nil {
		log.Error(err)
	}
	log.Debugf("opened the browser with url %s and err: %v", authInfo.VerificationURIComplete, err)
	if err != nil {
		log.Errorf("opening the browser page failed with: %v", err)
		return err
	}

	tctx, c := context.WithTimeout(context.TODO(), 90*time.Second)
	defer c()

	tokenInfo, err := auth0Client.WaitToken(tctx, authInfo)
	if err != nil {
		log.Error(err)
	}
	log.Debugf("received info: %v", tokenInfo)

	conn, err := s.client()
	if err != nil {
		log.Errorf("get client: %v", err)
		return err
	}

	request := proto.LoginRequest{
		JwtToken:      tokenInfo.AccessToken,
		PresharedKey:  "",
		ManagementUrl: managementURL,
	}
	err = WithBackOff(func() error {
		if _, err := conn.Login(s.ctx, &request); err != nil {
			log.Errorf("try login: %v", err)
		}
		return err
	})
	if err != nil {
		log.Errorf("backoff cycle failed: %v", err)
	}
	return err
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

	s.mStatus = systray.AddMenuItem("Disconnected", "Disconnected")
	s.mStatus.Disable()

	systray.AddSeparator()

	s.mUp = systray.AddMenuItem("Connect", "Connect")

	s.mDown = systray.AddMenuItem("Disconnect", "Disconnect")
	s.mDown.Disable()

	mURL := systray.AddMenuItem("Admin Panel", "Wiretrustee Admin Panel")

	systray.AddSeparator()

	mQuit := systray.AddMenuItem("Quit", "Quit the client app")

	go func() {
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
				if err = s.login(); err != nil {
					log.Debugf("got login error: %v", err)
					s.mUp.Enable()
				}
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
