package system

import (
	"context"
	"google.golang.org/grpc/metadata"
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

func WiretrusteeVersion() string {
	return version
}

func extractUserAgent(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		agent, ok := md["netbird-desktop-ui"]
		if ok {
			return agent[0]
		}
	}
	return ""
}
