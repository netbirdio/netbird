package cmd

const serverVNCAllowedFlag = "allow-server-vnc"

var serverVNCAllowed bool

func init() {
	upCmd.PersistentFlags().BoolVar(&serverVNCAllowed, serverVNCAllowedFlag, false, "Allow embedded VNC server on peer")
}
