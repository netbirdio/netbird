package cmd

import (
	"context"
	"runtime"

	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/internal"
)

type program struct {
	ctx    context.Context
	cancel context.CancelFunc
	serv   *grpc.Server
}

func init() {
	serviceCmd.AddCommand(runCmd, startCmd, stopCmd, restartCmd) // service control commands are subcommands of service
	serviceCmd.AddCommand(installCmd, uninstallCmd)              // service installer commands are subcommands of service
}

func newProgram(ctx context.Context, cancel context.CancelFunc) *program {
	ctx = internal.CtxInitState(ctx)
	return &program{ctx: ctx, cancel: cancel}
}

func newSVCConfig() *service.Config {
	name := "netbird"
	if runtime.GOOS == "windows" {
		name = "Netbird"
	}
	return &service.Config{
		Name:        name,
		DisplayName: "Netbird",
		Description: "A WireGuard-based mesh network that connects your devices into a single private network.",
		Option:      make(service.KeyValue),
	}
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
