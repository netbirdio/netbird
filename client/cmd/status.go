package cmd

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/client/internal/peer"
	nbStatus "github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/util"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

var detailFlag bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "status of the Netbird Service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		cmd.SetOut(cmd.OutOrStdout())

		err := util.InitLog(logLevel, "console")
		if err != nil {
			return fmt.Errorf("failed initializing log %v", err)
		}

		ctx := internal.CtxInitState(context.Background())

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			return fmt.Errorf("failed to connect to daemon error: %v\n"+
				"If the daemon is not running please run: "+
				"\nnetbird service install \nnetbird service start\n", err)
		}
		defer conn.Close()

		resp, err := proto.NewDaemonServiceClient(conn).Status(cmd.Context(), &proto.StatusRequest{GetFullPeerStatus: true})
		if err != nil {
			return fmt.Errorf("status failed: %v", status.Convert(err).Message())
		}

		cmd.Printf("Status: %s\n\n", resp.GetStatus())
		if resp.GetStatus() == string(internal.StatusNeedsLogin) || resp.GetStatus() == string(internal.StatusLoginFailed) {

			cmd.Printf("Run UP command to log in with SSO (interactive login):\n\n" +
				" netbird up \n\n" +
				"If you are running a self-hosted version and no SSO provider has been configured in your Management Server,\n" +
				"you can use a setup-key:\n\n netbird up --management-url <YOUR_MANAGEMENT_URL> --setup-key <YOUR_SETUP_KEY>\n\n" +
				"More info: https://www.netbird.io/docs/overview/setup-keys\n\n")
			return nil
		}

		pbFullStatus := resp.GetFullStatus()
		fullStatus := fromProtoFullStatus(pbFullStatus)

		cmd.Print(parseFullStatus(fullStatus, detailFlag))

		return nil
	},
}

func init() {
	statusCmd.PersistentFlags().BoolVar(&detailFlag, "detail", false, "display detailed status information")
}

func fromProtoFullStatus(pbFullStatus *proto.FullStatus) nbStatus.FullStatus {
	var fullStatus nbStatus.FullStatus

	fullStatus.ManagementState.URL = pbFullStatus.ManagementState.URL
	fullStatus.ManagementState.Connected = pbFullStatus.ManagementState.Connected

	fullStatus.SignalState.URL = pbFullStatus.SignalState.URL
	fullStatus.SignalState.Connected = pbFullStatus.SignalState.Connected

	fullStatus.LocalPeerState.IP = pbFullStatus.LocalPeerState.IP
	fullStatus.LocalPeerState.PubKey = pbFullStatus.LocalPeerState.PubKey
	fullStatus.LocalPeerState.KernelInterface = pbFullStatus.LocalPeerState.KernelInterface

	for _, pbPeerState := range pbFullStatus.Peers {
		peerState := nbStatus.PeerState{
			IP:                     pbPeerState.IP,
			PubKey:                 pbPeerState.PubKey,
			ConnStatus:             pbPeerState.ConnStatus,
			ConnStatusUpdate:       pbPeerState.ConnStatusUpdate.AsTime(),
			Relayed:                pbPeerState.Relayed,
			Direct:                 pbPeerState.Direct,
			LocalIceCandidateType:  pbPeerState.LocalIceCandidateType,
			RemoteIceCandidateType: pbPeerState.RemoteIceCandidateType,
		}
		fullStatus.Peers = append(fullStatus.Peers, peerState)
	}
	return fullStatus
}

func parseFullStatus(fullStatus nbStatus.FullStatus, printDetail bool) string {
	var (
		managementStatusURL     = ""
		signalStatusURL         = ""
		connectedPeersString    = ""
		disconnectedPeersString = ""
		managementConnString    = "Disconnected"
		signalConnString        = "Disconnected"
		InterfaceTypeString     = "Userspace"
		peersConnected          = 0
	)

	if printDetail {
		managementStatusURL = fmt.Sprintf(" to %s", fullStatus.ManagementState.URL)
		signalStatusURL = fmt.Sprintf(" to %s", fullStatus.SignalState.URL)
	}

	if fullStatus.ManagementState.Connected {
		managementConnString = "Connected"
	}

	if fullStatus.SignalState.Connected {
		signalConnString = "Connected"
	}

	if fullStatus.LocalPeerState.KernelInterface {
		InterfaceTypeString = "Kernel"
	}

	connectedStatusString := peer.StatusConnected.String()

	for _, peerState := range fullStatus.Peers {
		peerConnectionStatus := false
		if peerState.ConnStatus == connectedStatusString {
			peersConnected = peersConnected + 1
			peerConnectionStatus = true
		}

		if printDetail {
			localICE := "-"
			remoteICE := "-"
			connType := "-"

			if peerConnectionStatus {
				localICE = peerState.LocalIceCandidateType
				remoteICE = peerState.RemoteIceCandidateType
				connType = "P2P"
				if peerState.Relayed {
					connType = "Relayed"
				}
			}

			peerString := fmt.Sprintf(
				"\n Peer:\n"+
					"  NetBird IP: %s\n"+
					"  Public Key: %s\n"+
					"  Status: %s\n"+
					"  -- detail --\n"+
					"  Connection type: %s\n"+
					"  Direct: %t\n"+
					"  ICE Status (Local/Remote): %s/%s\n"+
					"  Last Connection Update: %s\n",
				peerState.IP,
				peerState.PubKey,
				peerState.ConnStatus,
				connType,
				peerState.Direct,
				localICE,
				remoteICE,
				peerState.ConnStatusUpdate,
			)

			if peerConnectionStatus {
				connectedPeersString = connectedPeersString + peerString
			} else {
				disconnectedPeersString = disconnectedPeersString + peerString
			}
		}
	}

	peersString := connectedPeersString + disconnectedPeersString + fmt.Sprintf("%d/%d Connected", peersConnected, len(fullStatus.Peers))

	return fmt.Sprintf("Management: %s%s\n"+
		"Signal:  %s%s\n"+
		"IP: %s\n"+
		"Interface Type: %s\n"+
		"Peers: %s\n",
		managementConnString,
		managementStatusURL,
		signalConnString,
		signalStatusURL,
		fullStatus.LocalPeerState.IP,
		InterfaceTypeString,
		peersString,
	)
}
