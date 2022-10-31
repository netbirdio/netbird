package cmd

import (
	"context"
	"fmt"
	cdns "github.com/netbirdio/netbird/client/internal/dns"
	nbdns "github.com/netbirdio/netbird/dns"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/server"
	"github.com/netbirdio/netbird/util"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

func (p *program) Start(svc service.Service) error {
	// Start should not block. Do the actual work async.
	log.Info("starting Netbird service") //nolint
	// in any case, even if configuration does not exists we run daemon to serve CLI gRPC API.
	p.serv = grpc.NewServer()

	split := strings.Split(daemonAddr, "://")
	switch split[0] {
	case "unix":
		// cleanup failed close
		stat, err := os.Stat(split[1])
		if err == nil && !stat.IsDir() {
			if err := os.Remove(split[1]); err != nil {
				log.Debugf("remove socket file: %v", err)
			}
		}
	case "tcp":
	default:
		return fmt.Errorf("unsupported daemon address protocol: %v", split[0])
	}

	listen, err := net.Listen(split[0], split[1])
	if err != nil {
		return fmt.Errorf("failed to listen daemon interface: %w", err)
	}
	go func() {
		defer listen.Close()

		if split[0] == "unix" {
			err = os.Chmod(split[1], 0666)
			if err != nil {
				log.Errorf("failed setting daemon permissions: %v", split[1])
				return
			}
		}

		dnsServer := cdns.NewServer(p.ctx)
		dnsServer.Start()
		defer dnsServer.Stop()

		err = dnsServer.UpdateDNSServer(1, nbdns.Update{
			CustomDomains: []nbdns.CustomDomain{
				{
					SearchDomain: []string{"netbird.cloud"},
					Records: []nbdns.SimpleRecord{
						{
							Name:  "peera.netbird.cloud",
							Type:  1,
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "1.2.3.4",
						},
						{
							Name:  "peerb.netbird.cloud",
							Type:  1,
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "5.6.7.8",
						},
					},
				},
			},
			NameServerGroups: []nbdns.NameServerGroup{
				{
					SearchDomains: []string{"wiretrustee.com", "netbird.io"},
					NameServers: []nbdns.NameServer{
						{
							IP:     netip.MustParseAddr("8.8.8.8"),
							NSType: nbdns.UDPNameServerType,
							Port:   53,
						},
						{
							IP:     netip.MustParseAddr("8.8.4.4"),
							NSType: nbdns.UDPNameServerType,
							Port:   53,
						},
					},
				},
				{
					SearchDomains: []string{"uol.com"},
					NameServers: []nbdns.NameServer{
						{
							IP:     netip.MustParseAddr("1.1.1.1"),
							NSType: nbdns.UDPNameServerType,
							Port:   53,
						},
						{
							IP:     netip.MustParseAddr("8.8.4.4"),
							NSType: nbdns.NameServerType(3),
							Port:   53,
						},
					},
				},
			},
		})

		if err != nil {
			panic(err)
		}

		serverInstance := server.New(p.ctx, managementURL, adminURL, configPath, logFile)
		if err := serverInstance.Start(); err != nil {
			log.Fatalf("failed to start daemon: %v", err)
		}
		proto.RegisterDaemonServiceServer(p.serv, serverInstance)

		log.Printf("started daemon server: %v", split[1])
		if err := p.serv.Serve(listen); err != nil {
			log.Errorf("failed to serve daemon requests: %v", err)
		}
	}()
	return nil
}

func (p *program) Stop(srv service.Service) error {
	p.cancel()

	if p.serv != nil {
		p.serv.Stop()
	}

	time.Sleep(time.Second * 2)
	log.Info("stopped Netbird service") //nolint
	return nil
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "runs Netbird as service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		cmd.SetOut(cmd.OutOrStdout())

		err := handleRebrand(cmd)
		if err != nil {
			return err
		}

		err = util.InitLog(logLevel, logFile)
		if err != nil {
			return fmt.Errorf("failed initializing log %v", err)
		}

		ctx, cancel := context.WithCancel(cmd.Context())
		SetupCloseHandler(ctx, cancel)

		s, err := newSVC(newProgram(ctx, cancel), newSVCConfig())
		if err != nil {
			return err
		}
		err = s.Run()
		if err != nil {
			return err
		}
		cmd.Printf("Netbird service is running")
		return nil
	},
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "starts Netbird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		cmd.SetOut(cmd.OutOrStdout())

		err := handleRebrand(cmd)
		if err != nil {
			return err
		}

		err = util.InitLog(logLevel, logFile)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithCancel(cmd.Context())

		s, err := newSVC(newProgram(ctx, cancel), newSVCConfig())
		if err != nil {
			cmd.PrintErrln(err)
			return err
		}
		err = s.Start()
		if err != nil {
			cmd.PrintErrln(err)
			return err
		}
		cmd.Println("Netbird service has been started")
		return nil
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "stops Netbird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		cmd.SetOut(cmd.OutOrStdout())

		err := handleRebrand(cmd)
		if err != nil {
			return err
		}

		err = util.InitLog(logLevel, logFile)
		if err != nil {
			return fmt.Errorf("failed initializing log %v", err)
		}

		ctx, cancel := context.WithCancel(cmd.Context())

		s, err := newSVC(newProgram(ctx, cancel), newSVCConfig())
		if err != nil {
			return err
		}
		err = s.Stop()
		if err != nil {
			return err
		}
		cmd.Println("Netbird service has been stopped")
		return nil
	},
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "restarts Netbird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		cmd.SetOut(cmd.OutOrStdout())

		err := handleRebrand(cmd)
		if err != nil {
			return err
		}

		err = util.InitLog(logLevel, logFile)
		if err != nil {
			return fmt.Errorf("failed initializing log %v", err)
		}

		ctx, cancel := context.WithCancel(cmd.Context())

		s, err := newSVC(newProgram(ctx, cancel), newSVCConfig())
		if err != nil {
			return err
		}
		err = s.Restart()
		if err != nil {
			return err
		}
		cmd.Println("Netbird service has been restarted")
		return nil
	},
}
