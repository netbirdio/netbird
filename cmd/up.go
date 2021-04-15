package cmd

import (
	"context"
	"fmt"
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/engine"
	sig "github.com/wiretrustee/wiretrustee/signal"
	"os"
	"strings"
)

const (
	ExitSetupFailed = 1
)

var (
	cfgFile string

	config = &Config{}

	upCmd = &cobra.Command{
		Use:   "up",
		Short: "start wiretrustee",
		Run: func(cmd *cobra.Command, args []string) {
			log.SetLevel(log.DebugLevel)

			ctx := context.Background()
			signalClient, err := sig.NewClient(config.SignalAddr, ctx)
			if err != nil {
				log.Errorf("error while connecting to the Signal Exchange Service %s: %s", config.SignalAddr, err)
				os.Exit(ExitSetupFailed)
			}
			//todo proper close handling
			defer func() { signalClient.Close() }()

			stunURL, _ := ice.ParseURL(config.StunURL)
			turnURL, _ := ice.ParseURL(config.TurnURL)
			turnURL.Password = config.TurnPwd
			turnURL.Username = config.TurnUser
			urls := []*ice.URL{turnURL, stunURL}

			engine := engine.NewEngine(signalClient, urls, config.WgIface, config.WgAddr)

			err = engine.Start(config.PrivateKey, strings.Split(config.Peers, ","))

			//signalClient.WaitConnected()

			SetupCloseHandler()
		},
	}
)

func init() {
	//upCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.wiretrustee.yaml)")
	upCmd.PersistentFlags().StringVar(&config.WgAddr, "address", "", "IP address of a peer in CIDR notation (e.g. 10.30.30.1/24)")
	upCmd.PersistentFlags().StringVar(&config.PrivateKey, "key", "", "Peers Wireguard private key")
	upCmd.PersistentFlags().StringVar(&config.Peers, "peers", "", "A comma separated list of peers (Wireguard public keys) to connect to")
	upCmd.MarkPersistentFlagRequired("key")
	upCmd.MarkPersistentFlagRequired("ip")
	upCmd.MarkPersistentFlagRequired("peers")
	upCmd.PersistentFlags().StringVar(&config.WgIface, "interface", "wiretrustee0", "Wireguard interface name")
	upCmd.PersistentFlags().StringVar(&config.StunURL, "stun", "stun:stun.wiretrustee.com:3468", "A comma separated list of STUN servers including protocol (e.g. stun:stun.wiretrustee.com:3468")
	upCmd.PersistentFlags().StringVar(&config.TurnURL, "turn", "turn:stun.wiretrustee.com:3468", "A comma separated list of TURN servers including protocol (e.g. stun:stun.wiretrustee.com:3468")
	upCmd.PersistentFlags().StringVar(&config.TurnUser, "turnUser", "wiretrustee", "A comma separated list of TURN servers including protocol (e.g. stun:stun.wiretrustee.com:3468")
	upCmd.PersistentFlags().StringVar(&config.TurnPwd, "turnPwd", "wt2021hello@", "A comma separated list of TURN servers including protocol (e.g. stun:stun.wiretrustee.com:3468")
	upCmd.PersistentFlags().StringVar(&config.SignalAddr, "signal", "signal.wiretrustee.com:10000", "Signal server URL (e.g. signal.wiretrustee.com:10000")
	//upCmd.MarkPersistentFlagRequired("config")
	fmt.Printf("")
}

func defaultConfig() *Config {

	return &Config{
		PrivateKey: "OCVgR9VJT4y4tBscRQ6SYHWocQlykUMCDI6APjp3ilY=",
		Peers:      "uRoZAk1g90WXXvazH0SS6URZ2/Kmhx+hbVhUt2ipzlU=",
		SignalAddr: "signal.wiretrustee.com:10000",
		StunURL:    "stun.wiretrustee.com:3468",
		TurnURL:    "stun.wiretrustee.com:3468",
		TurnPwd:    "wt2021hello@",
		TurnUser:   "wiretrustee",
		WgAddr:     "10.30.30.1/24",
		WgIface:    "wt0",
	}
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
