//go:build linux

// Package authdialog implements the stdout half of the protocol
// NetworkManager's secret-agent framework uses to talk to a VPN plugin's
// auth-dialog helper: the helper writes secrets back as newline-delimited
// key/value pairs, or a GKeyFile description when invoked in
// --external-ui-mode.
package authdialog

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/netbirdio/netbird/client/networkmanager/vpnplugin"
)

// noSecretKey is the sentinel key an auth-dialog writes with value "true" to
// tell NetworkManager that no secret prompt is needed at all.
const noSecretKey = "no-secret"

// WriteSecrets writes the given secrets to stdout in the key/value protocol
// NetworkManager expects back from an auth-dialog helper.
func WriteSecrets(w io.Writer, secrets map[string]string) error {
	bw := bufio.NewWriter(w)
	for key, value := range secrets {
		if _, err := fmt.Fprintf(bw, "%s\n%s\n", key, value); err != nil {
			return err
		}
	}
	if _, err := bw.WriteString("\n\n"); err != nil {
		return err
	}
	return bw.Flush()
}

// WriteNoSecretsRequired tells NetworkManager no prompt is needed at all.
func WriteNoSecretsRequired(w io.Writer) error {
	return WriteSecrets(w, map[string]string{noSecretKey: "true"})
}

// WriteExternalUI writes the "[VPN Plugin UI]" GKeyFile description
// NetworkManager's secret-agent framework expects when invoking the
// auth-dialog with --external-ui-mode. Title and Description live directly
// in the [VPN Plugin UI] group itself, not a separate section -- confirmed
// against gnome-shell's actual parser (js/ui/components/networkAgent.js),
// since getting this wrong produces an opaque "internal error" response
// with no other diagnostic. The field is marked ShouldAsk=false since
// nm-netbird-auth-dialog has already obtained everything it needs by
// opening the browser itself; the agent should accept the given value
// without prompting the user again.
func WriteExternalUI(w io.Writer, title, description, secretKey string) error {
	_, err := fmt.Fprintf(w,
		"[VPN Plugin UI]\nVersion=2\nTitle=%s\nDescription=%s\n\n[%s]\nValue=yes\nLabel=NetBird SSO\nIsSecret=false\nShouldAsk=false\n",
		title, description, secretKey)
	return err
}

// ParseHints extracts the SecretsRequired hint values nm-netbird-service
// encodes (see vpnplugin.HintVerificationURIPrefix/HintUserCodePrefix) out
// of the auth-dialog's repeated --hint arguments.
func ParseHints(hints []string) (verificationURI, userCode string) {
	for _, hint := range hints {
		switch {
		case strings.HasPrefix(hint, vpnplugin.HintVerificationURIPrefix):
			verificationURI = strings.TrimPrefix(hint, vpnplugin.HintVerificationURIPrefix)
		case strings.HasPrefix(hint, vpnplugin.HintUserCodePrefix):
			userCode = strings.TrimPrefix(hint, vpnplugin.HintUserCodePrefix)
		}
	}
	return verificationURI, userCode
}
