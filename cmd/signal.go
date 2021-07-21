package cmd

import (
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	sig "github.com/wiretrustee/wiretrustee/signal"
	sigProto "github.com/wiretrustee/wiretrustee/signal/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"net"
	"time"
)

var (
	signalPort int

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

			lis, err := net.Listen("tcp", fmt.Sprintf(":%d", signalPort))
			if err != nil {
				log.Fatalf("failed to listen: %v", err)
			}

			if err != nil {
				log.Fatalf("failed to listen: %v", err)
			}

			opts := []grpc.ServerOption{signalKaep, signalKasp}

			grpcServer := grpc.NewServer(opts...)
			sigProto.RegisterSignalExchangeServer(grpcServer, sig.NewServer())
			log.Printf("started server: localhost:%v", signalPort)
			if err := grpcServer.Serve(lis); err != nil {
				log.Fatalf("failed to serve: %v", err)
			}

			SetupCloseHandler()
			select {}
		},
	}
)

func init() {
	signalCmd.PersistentFlags().IntVar(&signalPort, "port", 10000, "Server port to listen on (e.g. 10000)")
}
