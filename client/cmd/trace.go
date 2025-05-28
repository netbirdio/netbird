package cmd

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

var traceCmd = &cobra.Command{
	Use:   "trace <direction> <source-ip> <dest-ip>",
	Short: "Trace a packet through the firewall",
	Example: `
  netbird debug trace in 192.168.1.10 10.10.0.2 -p tcp --sport 12345 --dport 443 --syn --ack
  netbird debug trace out 10.10.0.1 8.8.8.8 -p udp  --dport 53
  netbird debug trace in 10.10.0.2 10.10.0.1 -p icmp --icmp-type 8 --icmp-code 0
  netbird debug trace in 100.64.1.1 self -p tcp --dport 80`,
	Args: cobra.ExactArgs(3),
	RunE: tracePacket,
}

func init() {
	debugCmd.AddCommand(traceCmd)

	traceCmd.Flags().StringP("protocol", "p", "tcp", "Protocol (tcp/udp/icmp)")
	traceCmd.Flags().Uint16("sport", 0, "Source port")
	traceCmd.Flags().Uint16("dport", 0, "Destination port")
	traceCmd.Flags().Uint8("icmp-type", 0, "ICMP type")
	traceCmd.Flags().Uint8("icmp-code", 0, "ICMP code")
	traceCmd.Flags().Bool("syn", false, "TCP SYN flag")
	traceCmd.Flags().Bool("ack", false, "TCP ACK flag")
	traceCmd.Flags().Bool("fin", false, "TCP FIN flag")
	traceCmd.Flags().Bool("rst", false, "TCP RST flag")
	traceCmd.Flags().Bool("psh", false, "TCP PSH flag")
	traceCmd.Flags().Bool("urg", false, "TCP URG flag")
}

func tracePacket(cmd *cobra.Command, args []string) error {
	direction := strings.ToLower(args[0])
	if direction != "in" && direction != "out" {
		return fmt.Errorf("invalid direction: use 'in' or 'out'")
	}

	protocol := cmd.Flag("protocol").Value.String()
	if protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		return fmt.Errorf("invalid protocol: use tcp/udp/icmp")
	}

	sport, err := cmd.Flags().GetUint16("sport")
	if err != nil {
		return fmt.Errorf("invalid source port: %v", err)
	}
	dport, err := cmd.Flags().GetUint16("dport")
	if err != nil {
		return fmt.Errorf("invalid destination port: %v", err)
	}

	// For TCP/UDP, generate random ephemeral port (49152-65535) if not specified
	if protocol != "icmp" {
		if sport == 0 {
			sport = uint16(rand.Intn(16383) + 49152)
		}
		if dport == 0 {
			dport = uint16(rand.Intn(16383) + 49152)
		}
	}

	var tcpFlags *proto.TCPFlags
	if protocol == "tcp" {
		syn, _ := cmd.Flags().GetBool("syn")
		ack, _ := cmd.Flags().GetBool("ack")
		fin, _ := cmd.Flags().GetBool("fin")
		rst, _ := cmd.Flags().GetBool("rst")
		psh, _ := cmd.Flags().GetBool("psh")
		urg, _ := cmd.Flags().GetBool("urg")

		tcpFlags = &proto.TCPFlags{
			Syn: syn,
			Ack: ack,
			Fin: fin,
			Rst: rst,
			Psh: psh,
			Urg: urg,
		}
	}

	icmpType, _ := cmd.Flags().GetUint32("icmp-type")
	icmpCode, _ := cmd.Flags().GetUint32("icmp-code")

	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	resp, err := client.TracePacket(cmd.Context(), &proto.TracePacketRequest{
		SourceIp:        args[1],
		DestinationIp:   args[2],
		Protocol:        protocol,
		SourcePort:      uint32(sport),
		DestinationPort: uint32(dport),
		Direction:       direction,
		TcpFlags:        tcpFlags,
		IcmpType:        &icmpType,
		IcmpCode:        &icmpCode,
	})
	if err != nil {
		return fmt.Errorf("trace failed: %v", status.Convert(err).Message())
	}

	printTrace(cmd, args[1], args[2], protocol, sport, dport, resp)
	return nil
}

func printTrace(cmd *cobra.Command, src, dst, proto string, sport, dport uint16, resp *proto.TracePacketResponse) {
	cmd.Printf("Packet trace %s:%d -> %s:%d (%s)\n\n", src, sport, dst, dport, strings.ToUpper(proto))

	for _, stage := range resp.Stages {
		if stage.ForwardingDetails != nil {
			cmd.Printf("%s: %s [%s]\n", stage.Name, stage.Message, *stage.ForwardingDetails)
		} else {
			cmd.Printf("%s: %s\n", stage.Name, stage.Message)
		}
	}

	disposition := map[bool]string{
		true:  "\033[32mALLOWED\033[0m", // Green
		false: "\033[31mDENIED\033[0m",  // Red
	}[resp.FinalDisposition]

	cmd.Printf("\nFinal disposition: %s\n", disposition)
}
