package cmd

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"
	nbStatus "github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/util"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	"net/netip"
	"sort"
	"strings"
)

var (
	detailFlag   bool
	ipsFilter    []string
	statusFilter string
	ipsFilterMap map[string]struct{}
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "status of the Netbird Service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		cmd.SetOut(cmd.OutOrStdout())

		err := parseFilters()
		if err != nil {
			return err
		}

		err = util.InitLog(logLevel, "console")
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
	ipsFilterMap = make(map[string]struct{})
	statusCmd.PersistentFlags().BoolVarP(&detailFlag, "detail", "d", false, "display detailed status information")
	statusCmd.PersistentFlags().StringSliceVar(&ipsFilter, "filter-by-ips", []string{}, "filters the detailed output by a list of one or more IPs, e.g. --filter-by-ips 100.64.0.100,100.64.0.200")
	statusCmd.PersistentFlags().StringVar(&statusFilter, "filter-by-status", "", "filters the detailed output by connection status(connected|disconnected), e.g. --filter-by-status connected")
}

func parseFilters() error {
	switch strings.ToLower(statusFilter) {
	case "disconnected", "connected":
	default:
		return fmt.Errorf("wrong status filter, should be one of connected|disconnected, got: %s", statusFilter)
	}

	if len(ipsFilter) > 0 {
		for _, addr := range ipsFilter {
			_, err := netip.ParseAddr(addr)
			if err != nil {
				return fmt.Errorf("got an invalid IP address in the filter: address %s, error %s", addr, err)
			}
			ipsFilterMap[addr] = struct{}{}
		}
	}
	return nil
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

	var peersState []nbStatus.PeerState

	for _, pbPeerState := range pbFullStatus.Peers {
		timeLocal := pbPeerState.ConnStatusUpdate.AsTime().Local()
		peerState := nbStatus.PeerState{
			IP:                     pbPeerState.IP,
			PubKey:                 pbPeerState.PubKey,
			ConnStatus:             pbPeerState.ConnStatus,
			ConnStatusUpdate:       timeLocal,
			Relayed:                pbPeerState.Relayed,
			Direct:                 pbPeerState.Direct,
			LocalIceCandidateType:  pbPeerState.LocalIceCandidateType,
			RemoteIceCandidateType: pbPeerState.RemoteIceCandidateType,
		}
		peersState = append(peersState, peerState)
	}

	fullStatus.Peers = peersState

	return fullStatus
}

func parseFullStatus(fullStatus nbStatus.FullStatus, printDetail bool) string {
	var (
		managementStatusURL  = ""
		signalStatusURL      = ""
		managementConnString = "Disconnected"
		signalConnString     = "Disconnected"
		InterfaceTypeString  = "Userspace"
		peersConnected       = 0
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

	parsedPeersString, peersConnected := parsePeers(fullStatus.Peers, printDetail)

	peersString := parsedPeersString + fmt.Sprintf("%d/%d Connected", peersConnected, len(fullStatus.Peers))

	return fmt.Sprintf(
		"Management: %s%s\n"+
			"Signal:  %s%s\n"+
			"IP: %s\n"+
			"Interface type: %s\n"+
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

func parsePeers(peers []nbStatus.PeerState, printDetail bool) (string, int) {
	var (
		peersString    = ""
		peersConnected = 0
	)

	if len(peers) > 0 {
		sort.SliceStable(peers, func(i, j int) bool {
			iAddr, _ := netip.ParseAddr(peers[i].IP)
			jAddr, _ := netip.ParseAddr(peers[j].IP)
			return iAddr.Compare(jAddr) == -1
		})
	}

	connectedStatusString := peer.StatusConnected.String()

	for _, peerState := range peers {
		peerConnectionStatus := false
		if peerState.ConnStatus == connectedStatusString {
			peersConnected = peersConnected + 1
			peerConnectionStatus = true
		}

		if printDetail {

			if skipDetailByFilters(peerState, peerConnectionStatus) {
				continue
			}

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
					"  Public key: %s\n"+
					"  Status: %s\n"+
					"  -- detail --\n"+
					"  Connection type: %s\n"+
					"  Direct: %t\n"+
					"  ICE candidate (Local/Remote): %s/%s\n"+
					"  Last connection update: %s\n",
				peerState.IP,
				peerState.PubKey,
				peerState.ConnStatus,
				connType,
				peerState.Direct,
				localICE,
				remoteICE,
				peerState.ConnStatusUpdate.Format("2006-01-02 15:04:05"),
			)

			peersString = peersString + peerString
		}
	}
	return peersString, peersConnected
}

func skipDetailByFilters(peerState nbStatus.PeerState, isConnected bool) bool {
	statusEval := false
	ipEval := false

	if statusFilter != "" {
		lowerStatusFilter := strings.ToLower(statusFilter)
		if lowerStatusFilter == "disconnected" && isConnected {
			statusEval = true
		} else if lowerStatusFilter == "connected" && !isConnected {
			statusEval = true
		}
	}

	if len(ipsFilter) > 0 {
		_, ok := ipsFilterMap[peerState.IP]
		if !ok {
			ipEval = true
		}
	}
	return statusEval || ipEval
}
