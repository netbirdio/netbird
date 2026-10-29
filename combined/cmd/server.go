package cmd

import (
	mgmtServer "github.com/netbirdio/netbird/management/internals/server"
)

var newServer = func(cfg *mgmtServer.Config) mgmtServer.Server {
	return mgmtServer.NewServer(cfg)
}

func SetNewServer(fn func(*mgmtServer.Config) mgmtServer.Server) {
	newServer = fn
}
