package wiretrustee

import (
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/signal"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	"os"
)

const (
	ExitSetupFailed = 1
)

func init() {
	runCmd := &cobra.Command{
		Use:   "start",
		Short: "start wiretrustee",
		Run: func(cmd *cobra.Command, args []string) {
			config, err := ReadConfig("config.yml")
			if err != nil {
				log.Fatal("failed to load config")
				os.Exit(ExitSetupFailed)
			}

			//todo print config

			//todo connect to signal
			ctx := context.Background()
			signalClient, err := signal.NewClient(config.SignalAddr, ctx)
			if err != nil {
				log.Errorf("error while connecting to the Signal Exchange Service %s: %s", config.SignalAddr, err)
				os.Exit(ExitSetupFailed)
			}
			//todo proper close handling
			defer func() { signalClient.Close() }()

			signalClient.WaitConnected()

			select {}
		},
	}
	rootCmd.AddCommand(runCmd)
}

func ReadConfig(path string) (*Config, error) {
	/*f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bs, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var cfg Config

	err = yaml.Unmarshal(bs, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil*/

	return &Config{}, nil
}
