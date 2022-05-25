package system

import (
	"context"
	"google.golang.org/grpc/metadata"
	"strings"
)

// this is the wiretrustee version
// will be replaced with the release version when using goreleaser
var version = "development"

//Info is an object that contains machine information
// Most of the code is taken from https://github.com/matishsiao/goInfo
type Info struct {
	GoOS               string
	Kernel             string
	Core               string
	Platform           string
	OS                 string
	OSVersion          string
	Hostname           string
	CPUs               int
	WiretrusteeVersion string
	UIVersion          string
}

func NetbirdVersion() string {
	return version
}

// extractUserAgent extracts Netbird's agent (client) name and version from the outgoing context
func extractUserAgent(ctx context.Context) string {
	md, hasMeta := metadata.FromOutgoingContext(ctx)
	if hasMeta {
		agent, ok := md["user-agent"]
		if ok {
			nbAgent := strings.Split(agent[0], " ")[0]
			if strings.HasPrefix(nbAgent, "netbird") {
				return nbAgent
			}
			return ""
		}
	}
	return ""
}

func GetDesktopUIUserAgent() string {
	return "netbird-desktop-ui/" + NetbirdVersion()
}
