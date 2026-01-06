package debug

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/iface/configurer"
)

type WGIface interface {
	FullStats() (*configurer.Stats, error)
}

func (g *BundleGenerator) addWgShow() error {
	if g.statusRecorder == nil {
		return fmt.Errorf("no status recorder available for wg show")
	}
	result, err := g.statusRecorder.PeersStatus()
	if err != nil {
		return err
	}

	output := g.toWGShowFormat(result)
	reader := bytes.NewReader([]byte(output))

	if err := g.addFileToZip(reader, "wgshow.txt"); err != nil {
		return fmt.Errorf("add wg show to zip: %w", err)
	}
	return nil
}

func (g *BundleGenerator) toWGShowFormat(s *configurer.Stats) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("interface: %s\n", s.DeviceName))
	sb.WriteString(fmt.Sprintf("  public key: %s\n", s.PublicKey))
	sb.WriteString(fmt.Sprintf("  listen port: %d\n", s.ListenPort))
	if s.FWMark != 0 {
		sb.WriteString(fmt.Sprintf("  fwmark: %#x\n", s.FWMark))
	}

	for _, peer := range s.Peers {
		sb.WriteString(fmt.Sprintf("\npeer: %s\n", peer.PublicKey))
		if peer.Endpoint.IP != nil {
			if g.anonymize {
				anonEndpoint := g.anonymizer.AnonymizeUDPAddr(peer.Endpoint)
				sb.WriteString(fmt.Sprintf("  endpoint: %s\n", anonEndpoint.String()))
			} else {
				sb.WriteString(fmt.Sprintf("  endpoint: %s\n", peer.Endpoint.String()))
			}
		}
		if len(peer.AllowedIPs) > 0 {
			var ipStrings []string
			for _, ipnet := range peer.AllowedIPs {
				ipStrings = append(ipStrings, ipnet.String())
			}
			sb.WriteString(fmt.Sprintf("  allowed ips: %s\n", strings.Join(ipStrings, ", ")))
		}
		sb.WriteString(fmt.Sprintf("  latest handshake: %s\n", peer.LastHandshake.Format(time.RFC1123)))
		sb.WriteString(fmt.Sprintf("  transfer: %d B received, %d B sent\n", peer.RxBytes, peer.TxBytes))
		if peer.PresharedKey != [32]byte{} {
			sb.WriteString("  preshared key: (hidden)\n")
		}
	}

	return sb.String()
}
