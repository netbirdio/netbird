//go:build !linux || android

package server

import (
	"archive/zip"

	"github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/proto"
)

// collectFirewallRules returns nothing on non-linux systems
func (s *Server) addFirewallRules(req *proto.DebugBundleRequest, anonymizer *anonymize.Anonymizer, archive *zip.Writer) error {
	return nil
}
