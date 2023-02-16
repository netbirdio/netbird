package iface

import (
	"encoding/hex"
	"fmt"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func toWgUserspaceString(wgCfg wgtypes.Config) string {
	var sb strings.Builder
	if wgCfg.PrivateKey != nil {
		hexKey := hex.EncodeToString(wgCfg.PrivateKey[:])
		sb.WriteString(fmt.Sprintf("private_key=%s\n", hexKey))
	}

	if wgCfg.ListenPort != nil {
		sb.WriteString(fmt.Sprintf("listen_port=%d\n", *wgCfg.ListenPort))
	}

	if wgCfg.ReplacePeers {
		sb.WriteString("replace_peers=true\n")
	}

	if wgCfg.FirewallMark != nil {
		sb.WriteString(fmt.Sprintf("fwmark=%d\n", *wgCfg.FirewallMark))
	}

	for _, p := range wgCfg.Peers {
		hexKey := hex.EncodeToString(p.PublicKey[:])
		sb.WriteString(fmt.Sprintf("public_key=%s\n", hexKey))

		if p.PresharedKey != nil {
			preSharedHexKey := hex.EncodeToString(p.PresharedKey[:])
			sb.WriteString(fmt.Sprintf("public_key=%s\n", preSharedHexKey))
		}

		if p.ReplaceAllowedIPs {
			sb.WriteString("replace_allowed_ips=true\n")
		}

		for _, aip := range p.AllowedIPs {
			sb.WriteString(fmt.Sprintf("allowed_ip=%s\n", aip.String()))
		}

		if p.Endpoint != nil {
			sb.WriteString(fmt.Sprintf("endpoint=%s\n", p.Endpoint.String()))
		}

		if p.PersistentKeepaliveInterval != nil {
			// todo: is it Seconds?
			sb.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", p.PersistentKeepaliveInterval.Milliseconds()))
		}
	}
	return sb.String()
}
