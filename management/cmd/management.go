package cmd

import (
	"flag"
	"fmt"
	"github.com/wiretrustee/wiretrustee/management/server"
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
	mgmtHostsConfig       string
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

			config := &server.HostsConfig{}
			_, err := util.ReadJson(mgmtHostsConfig, config)
			if err != nil {
				log.Fatalf("failed reading provided config file: %s: %v", mgmtHostsConfig, err)
			}

			if _, err := os.Stat(mgmtDataDir); os.IsNotExist(err) {
				err = os.MkdirAll(mgmtDataDir, os.ModeDir)
				if err != nil {
					log.Fatalf("failed creating datadir: %s: %v", mgmtDataDir, err)
				}
			}

			var opts []grpc.ServerOption

			if mgmtLetsencryptDomain != "" {
				transportCredentials := credentials.NewTLS(encryption.EnableLetsEncrypt(mgmtDataDir, mgmtLetsencryptDomain))
				opts = append(opts, grpc.Creds(transportCredentials))
			}

			opts = append(opts, grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
			grpcServer := grpc.NewServer(opts...)

			server, err := server.NewServer(mgmtDataDir, config)
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

			SetupCloseHandler()
			<-stopCh
			log.Println("Receive signal to stop running Management server")
		},
	}
)

func init() {
	mgmtCmd.Flags().IntVar(&mgmtPort, "port", 33073, "server port to listen on")
	mgmtCmd.Flags().StringVar(&mgmtDataDir, "datadir", "/var/lib/wiretrustee/", "server data directory location")
	mgmtCmd.Flags().StringVar(&mgmtHostsConfig, "hosts-config", "/etc/wiretrustee/hosts-config.json", "Wiretrustee system hosts config (STUN, TURN, Signal, etc). These will be advertised to peers ")
	mgmtCmd.Flags().StringVar(&mgmtLetsencryptDomain, "letsencrypt-domain", "", "a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")

	rootCmd.MarkFlagRequired("hosts-config") //nolint

}
