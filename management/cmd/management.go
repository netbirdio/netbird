package cmd

import (
	"context"
	"flag"
	"fmt"
	"github.com/wiretrustee/wiretrustee/management/server"
	grpc2 "github.com/wiretrustee/wiretrustee/management/server/grpc"
	"github.com/wiretrustee/wiretrustee/management/server/http"
	"github.com/wiretrustee/wiretrustee/util"
	"net"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/encryption"
	mgmtProto "github.com/wiretrustee/wiretrustee/management/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

var (
	mgmtPort              int
	mgmtDataDir           string
	mgmtConfig            string
	mgmtLetsencryptDomain string

	kaep = keepalive.EnforcementPolicy{
		MinTime:             15 * time.Second,
		PermitWithoutStream: true,
	}

	kasp = keepalive.ServerParameters{
		MaxConnectionIdle:     15 * time.Second,
		MaxConnectionAgeGrace: 5 * time.Second,
		Time:                  5 * time.Second,
		Timeout:               2 * time.Second,
	}

	mgmtCmd = &cobra.Command{
		Use:   "management",
		Short: "start Wiretrustee Management Server",
		Run: func(cmd *cobra.Command, args []string) {
			flag.Parse()

			config, err := loadConfig()
			if err != nil {
				log.Fatalf("failed reading provided config file: %s: %v", mgmtConfig, err)
			}

			if _, err = os.Stat(config.Datadir); os.IsNotExist(err) {
				err = os.MkdirAll(config.Datadir, os.ModeDir)
				if err != nil {
					log.Fatalf("failed creating datadir: %s: %v", config.Datadir, err)
				}
			}

			store, err := server.NewStore(config.Datadir)
			if err != nil {
				log.Fatalf("failed creating a store: %s: %v", config.Datadir, err)
			}
			accountManager := server.NewManager(store)

			var opts []grpc.ServerOption

			var httpServer *http.Server
			if config.HttpConfig.LetsEncryptDomain != "" {
				certManager := encryption.CreateCertManager(config.Datadir, config.HttpConfig.LetsEncryptDomain)
				transportCredentials := credentials.NewTLS(certManager.TLSConfig())
				opts = append(opts, grpc.Creds(transportCredentials))

				httpServer = http.NewHttpsServer(config.HttpConfig, certManager, accountManager)
			} else {
				httpServer = http.NewHttpServer(config.HttpConfig, accountManager)
			}

			opts = append(opts, grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
			grpcServer := grpc.NewServer(opts...)

			server, err := grpc2.NewServer(config, accountManager)
			if err != nil {
				log.Fatalf("failed creating new server: %v", err)
			}
			mgmtProto.RegisterManagementServiceServer(grpcServer, server)
			log.Printf("started server: localhost:%v", mgmtPort)

			lis, err := net.Listen("tcp", fmt.Sprintf(":%d", mgmtPort))
			if err != nil {
				log.Fatalf("failed to listen: %v", err)
			}

			go func() {
				if err = grpcServer.Serve(lis); err != nil {
					log.Fatalf("failed to serve gRpc server: %v", err)
				}
			}()

			go func() {
				err = httpServer.Start()
				if err != nil {
					log.Fatalf("failed to serve http server: %v", err)
				}
			}()

			SetupCloseHandler()
			<-stopCh
			log.Println("Receive signal to stop running Management server")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err = httpServer.Stop(ctx)
			if err != nil {
				log.Fatalf("failed stopping the http server %v", err)
			}

			grpcServer.Stop()
		},
	}
)

func loadConfig() (*server.Config, error) {
	config := &server.Config{}
	_, err := util.ReadJson(mgmtConfig, config)
	if err != nil {
		return nil, err
	}
	if mgmtLetsencryptDomain != "" {
		config.HttpConfig.LetsEncryptDomain = mgmtLetsencryptDomain
	}
	if mgmtDataDir != "" {
		config.Datadir = mgmtDataDir
	}

	return config, err
}

func init() {
	mgmtCmd.Flags().IntVar(&mgmtPort, "port", 33073, "server port to listen on")
	mgmtCmd.Flags().StringVar(&mgmtDataDir, "datadir", "/var/lib/wiretrustee/", "server data directory location")
	mgmtCmd.Flags().StringVar(&mgmtConfig, "config", "/etc/wiretrustee/management.json", "Wiretrustee config file location. Config params specified via command line (e.g. datadir) have a precedence over configuration from this file")
	mgmtCmd.Flags().StringVar(&mgmtLetsencryptDomain, "letsencrypt-domain", "", "a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")

	rootCmd.MarkFlagRequired("config") //nolint

}
