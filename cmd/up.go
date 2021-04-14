package cmd

import (
	"context"
	"fmt"
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/engine"
	"github.com/wiretrustee/wiretrustee/signal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"os"
)

const (
	ExitSetupFailed = 1
)

var (
	cfgFile string

	upCmd = &cobra.Command{
		Use:   "up",
		Short: "start wiretrustee",
		Run: func(cmd *cobra.Command, args []string) {
			/*config, err := ReadConfig("config.yml")
			if err != nil {
				log.Fatal("failed to load config")
				os.Exit(ExitSetupFailed)
			}*/

			c := defaultConfig()

			//todo print config

			//todo connect to signal
			ctx := context.Background()
			signalClient, err := signal.NewClient(c.SignalAddr, ctx)
			if err != nil {
				log.Errorf("error while connecting to the Signal Exchange Service %s: %s", c.SignalAddr, err)
				os.Exit(ExitSetupFailed)
			}
			//todo proper close handling
			defer func() { signalClient.Close() }()

			stunURL, _ := ice.ParseURL(fmt.Sprintf("stun:%s", c.StunURL))
			turnURL, _ := ice.ParseURL(fmt.Sprintf("turn:%s", c.StunURL))
			turnURL.Password = c.TurnPwd
			turnURL.Username = c.TurnUser
			urls := []*ice.URL{turnURL, stunURL}

			s := c.PrivateKey.PublicKey().String()

			engine := engine.NewEngine(signalClient, urls, c.WgIface, c.WgAddr)
			err = engine.Start(s, c.Peers)

			signalClient.WaitConnected()

			select {}
		},
	}
)

func init() {
	upCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.wiretrustee.yaml)")
	//upCmd.MarkPersistentFlagRequired("config")
	fmt.Printf("")
}

func defaultConfig() *Config {

	key, _ := wgtypes.ParseKey("OCVgR9VJT4y4tBscRQ6SYHWocQlykUMCDI6APjp3ilY=")

	return &Config{
		PrivateKey: key,
		Peers:      []string{"uRoZAk1g90WXXvazH0SS6URZ2/Kmhx+hbVhUt2ipzlU="},
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
