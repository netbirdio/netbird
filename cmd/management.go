package cmd

import (
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/common"
	mgmt "github.com/wiretrustee/wiretrustee/management"
	mgmtProto "github.com/wiretrustee/wiretrustee/management/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"net"
	"os"
	"time"
)

var (
	mgmtPort              int
	mgmtDataDir           string
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

			if _, err := os.Stat(mgmtDataDir); os.IsNotExist(err) {
				err = os.MkdirAll(mgmtDataDir, os.ModeDir)
				if err != nil {
					log.Fatalf("failed creating datadir: %s: %v", mgmtDataDir, err)
				}
			}

			var opts []grpc.ServerOption

			if mgmtLetsencryptDomain != "" {
				transportCredentials := credentials.NewTLS(common.EnableLetsEncrypt(mgmtDataDir, mgmtLetsencryptDomain))
				opts = append(opts, grpc.Creds(transportCredentials))
			}

			opts = append(opts, grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
			grpcServer := grpc.NewServer(opts...)

			server, err := mgmt.NewServer(mgmtDataDir)
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
	mgmtCmd.Flags().StringVar(&mgmtLetsencryptDomain, "letsencrypt-domain", "", "a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")
}
