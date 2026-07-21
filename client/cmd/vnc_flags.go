package cmd

const (
	serverVNCAllowedFlag   = "allow-server-vnc"
	disableVNCApprovalFlag = "disable-vnc-approval"
)

var (
	serverVNCAllowed   bool
	disableVNCApproval bool
)

func init() {
	upCmd.PersistentFlags().BoolVar(&serverVNCAllowed, serverVNCAllowedFlag, false, "Allow embedded VNC server on peer")
	upCmd.PersistentFlags().BoolVar(&disableVNCApproval, disableVNCApprovalFlag, false, "Disable per-connection user approval prompts for the embedded VNC server")
}
