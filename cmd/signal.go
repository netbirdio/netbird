package cmd

import (
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/encryption"
	sigProto "github.com/wiretrustee/wiretrustee/signal/proto"
	"github.com/wiretrustee/wiretrustee/signal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"net"
	"os"
	"time"
)

var (
	signalPort              int
	signalLetsencryptDomain string
	signalDataDir           string

	signalKaep = grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
		MinTime:             5 * time.Second,
		PermitWithoutStream: true,
	})

	signalKasp = grpc.KeepaliveParams(keepalive.ServerParameters{
		MaxConnectionIdle:     15 * time.Second,
		MaxConnectionAgeGrace: 5 * time.Second,
		Time:                  5 * time.Second,
		Timeout:               2 * time.Second,
	})

	signalCmd = &cobra.Command{
		Use:   "signal",
		Short: "start Wiretrustee Signal Server",
		Run: func(cmd *cobra.Command, args []string) {
			flag.Parse()

			if _, err := os.Stat(signalDataDir); os.IsNotExist(err) {
				err = os.MkdirAll(signalDataDir, os.ModeDir)
				if err != nil {
					log.Fatalf("failed creating datadir: %s: %v", signalDataDir, err)
				}
			}

			var opts []grpc.ServerOption
			if signalLetsencryptDomain != "" {
				certManager := encryption.CreateCertManager(signalDataDir, signalLetsencryptDomain)
				transportCredentials := credentials.NewTLS(certManager.TLSConfig())
				opts = append(opts, grpc.Creds(transportCredentials))
			}

			opts = append(opts, signalKaep, signalKasp)
			grpcServer := grpc.NewServer(opts...)

			lis, err := net.Listen("tcp", fmt.Sprintf(":%d", signalPort))
			if err != nil {
				log.Fatalf("failed to listen: %v", err)
			}

			if err != nil {
				log.Fatalf("failed to listen: %v", err)
			}

			sigProto.RegisterSignalExchangeServer(grpcServer, server.NewServer())
			log.Printf("started server: localhost:%v", signalPort)
			if err := grpcServer.Serve(lis); err != nil {
				log.Fatalf("failed to serve: %v", err)
			}

			SetupCloseHandler()
			<-stopCh
			log.Println("Receive signal to stop running the Signal server")
		},
	}
)

func init() {
	signalCmd.PersistentFlags().IntVar(&signalPort, "port", 10000, "Server port to listen on (e.g. 10000)")
	signalCmd.Flags().StringVar(&signalDataDir, "datadir", "/var/lib/wiretrustee/", "server data directory location")
	signalCmd.Flags().StringVar(&signalLetsencryptDomain, "letsencrypt-domain", "", "a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")
}
