package cmd

import (
	"context"
	"runtime"
	"sync"

	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/server"
)

type program struct {
	ctx              context.Context
	cancel           context.CancelFunc
	serv             *grpc.Server
	serverInstance   *server.Server
	serverInstanceMu sync.Mutex
}

func newProgram(ctx context.Context, cancel context.CancelFunc) *program {
	ctx = internal.CtxInitState(ctx)
	return &program{ctx: ctx, cancel: cancel}
}

func newSVCConfig() *service.Config {
	config := &service.Config{
		Name:        serviceName,
		DisplayName: "Netbird",
		Description: "A WireGuard-based mesh network that connects your devices into a single private network.",
		Option:      make(service.KeyValue),
		EnvVars:     make(map[string]string),
	}

	// Set SYSTEMD_UNIT environment variable for Linux systems
	if runtime.GOOS == "linux" {
		config.EnvVars["SYSTEMD_UNIT"] = serviceName
	}

	return config
}

func newSVC(prg *program, conf *service.Config) (service.Service, error) {
	s, err := service.New(prg, conf)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return s, nil
}

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "manages Netbird service",
}
