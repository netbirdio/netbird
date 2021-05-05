package cmd

import (
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"os"
	"strings"
)

var (
	wgKey       string
	wgInterface string
	wgLocalAddr string
	signalAddr  string
	stunURLs    string
	turnURLs    string

	initCmd = &cobra.Command{
		Use:   "init",
		Short: "init wiretrustee",
		Run: func(cmd *cobra.Command, args []string) {
			InitLog(logLevel)

			if _, err := os.Stat(configPath); !os.IsNotExist(err) {
				log.Warnf("config already exists under path %s", configPath)
				os.Exit(ExitSetupFailed)
			}

			if wgKey == "" {
				wgKey = generateKey()
				log.Warnf("there was no Wireguard private key specified, a new Wireguard key has been generated")
			}

			parsedKey, err := wgtypes.ParseKey(wgKey)
			if err != nil {
				log.Errorf("invalid Wireguard private key %s", wgKey)
				os.Exit(ExitSetupFailed)
			}

			log.Infof("my public Wireguard key is %s", parsedKey.PublicKey().String())

			var stunTurnURLs []*ice.URL
			stuns := strings.Split(stunURLs, ",")
			for _, url := range stuns {

				parsedURL, err := ice.ParseURL(url)
				if err != nil {
					log.Errorf("failed parsing STUN URL %s: %s", url, err.Error())
					os.Exit(ExitSetupFailed)
				}
				stunTurnURLs = append(stunTurnURLs, parsedURL)
			}

			turns := strings.Split(turnURLs, ",")
			for _, url := range turns {

				var urlToParse string
				var user string
				var pwd string
				//extract user:password from user:password@proto:host:port
				urlSplit := strings.Split(url, "@")
				if len(urlSplit) == 2 {
					urlToParse = urlSplit[1]
					credential := strings.Split(urlSplit[0], ":")
					user = credential[0]
					pwd = credential[1]
				} else {
					urlToParse = url
				}

				parsedURL, err := ice.ParseURL(urlToParse)
				if err != nil {
					log.Errorf("failed parsing TURN URL %s: %s", url, err.Error())
					os.Exit(ExitSetupFailed)
				}
				parsedURL.Username = user
				parsedURL.Password = pwd
				stunTurnURLs = append(stunTurnURLs, parsedURL)
			}

			config := &Config{
				PrivateKey:   wgKey,
				Peers:        nil,
				StunTurnURLs: stunTurnURLs,
				SignalAddr:   signalAddr,
				WgAddr:       wgLocalAddr,
				WgIface:      wgInterface,
			}

			err = config.Write(configPath)
			if err != nil {
				log.Errorf("failed writing config to %s: %s", config, err.Error())
				os.Exit(ExitSetupFailed)
			}

			log.Infof("a new config has been generated and written to %s", configPath)
		},
	}
)

func init() {
	initCmd.PersistentFlags().StringVar(&wgKey, "wgKey", "", "Wireguard private key, if not specified a new one will be generated")
	initCmd.PersistentFlags().StringVar(&wgInterface, "wgInterface", "wiretrustee0", "Wireguard interface name, e.g. wiretreustee0 or wg0")
	initCmd.PersistentFlags().StringVar(&wgLocalAddr, "wgLocalAddr", "", "Wireguard local address, e.g. 10.30.30.1/24")
	initCmd.PersistentFlags().StringVar(&signalAddr, "signalAddr", "", "Signal server address, e.g. signal.wiretrustee.com:10000")
	initCmd.PersistentFlags().StringVar(&stunURLs, "stunURLs", "", "Comma separated STUN server URLs: protocol:host:port, e.g. stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302")
	//todo user:password@protocol:host:port not the best way to pass TURN credentials, do it according to https://tools.ietf.org/html/rfc7065 E.g. use oauth
	initCmd.PersistentFlags().StringVar(&turnURLs, "turnURLs", "", "Comma separated TURN server URLs: user:password@protocol:host:port, e.g. user:password@turn:stun.wiretrustee.com:3468")
	//initCmd.MarkPersistentFlagRequired("configPath")
	initCmd.MarkPersistentFlagRequired("wgLocalAddr")
	initCmd.MarkPersistentFlagRequired("signalAddr")
	initCmd.MarkPersistentFlagRequired("stunURLs")
	initCmd.MarkPersistentFlagRequired("turnURLs")
}

// generateKey generates a new Wireguard private key
func generateKey() string {
	key, err := wgtypes.GenerateKey()
	if err != nil {
		panic(err)
	}
	return key.String()
}
