package cmd

import (
	"context"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/encryption"
	"github.com/wiretrustee/wiretrustee/signal/peer"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	"github.com/wiretrustee/wiretrustee/signal/server"
	"github.com/wiretrustee/wiretrustee/signal/server/http"
	"github.com/wiretrustee/wiretrustee/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"net"
	"time"
)

var (
	signalPort              int
	signalLetsencryptDomain string
	signalSSLDir            string

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

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "start Wiretrustee Signal Server daemon",
		Run: func(cmd *cobra.Command, args []string) {
			flag.Parse()
			err := util.InitLog(logLevel, logFile)
			if err != nil {
				log.Fatalf("failed initializing log %v", err)
			}

			registry := peer.NewRegistry()

			var opts []grpc.ServerOption
			var httpServer *http.Server
			if signalLetsencryptDomain != "" {

				//automatically generate a new certificate with Let's Encrypt
				certManager := encryption.CreateCertManager(signalSSLDir, signalLetsencryptDomain)
				transportCredentials := credentials.NewTLS(certManager.TLSConfig())
				opts = append(opts, grpc.Creds(transportCredentials))

				httpServer = http.NewHttpsServer("0.0.0.0:443", certManager, registry)
			} else {
				httpServer = http.NewHttpServer("0.0.0.0:80", registry)
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

			proto.RegisterSignalExchangeServer(grpcServer, server.NewServer(registry))
			log.Printf("gRPC server listening on 0.0.0.0:%v", signalPort)

			go func() {
				if err := grpcServer.Serve(lis); err != nil {
					log.Fatalf("failed to serve: %v", err)
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
			log.Println("received signal to stop running the Signal server")

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

func init() {
	runCmd.PersistentFlags().IntVar(&signalPort, "port", 10000, "Server port to listen on (e.g. 10000)")
	runCmd.Flags().StringVar(&signalSSLDir, "ssl-dir", "/var/lib/wiretrustee/", "server ssl directory location. *Required only for Let's Encrypt certificates.")
	runCmd.Flags().StringVar(&signalLetsencryptDomain, "letsencrypt-domain", "", "a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")
}
