package cmd

import (
	"fmt"

	"github.com/netbirdio/netbird/management/internals/server"
)

const (
	defaultMgmtDataDir   = "/var/lib/netbird/"
	defaultMgmtConfigDir = "/etc/netbird"
	defaultLogDir        = "/var/log/netbird"

	oldDefaultMgmtDataDir   = "/var/lib/wiretrustee/"
	oldDefaultMgmtConfigDir = "/etc/wiretrustee"
	oldDefaultLogDir        = "/var/log/wiretrustee"

	defaultMgmtConfig    = defaultMgmtConfigDir + "/management.json"
	defaultLogFile       = defaultLogDir + "/management.log"
	oldDefaultMgmtConfig = oldDefaultMgmtConfigDir + "/management.json"
	oldDefaultLogFile    = oldDefaultLogDir + "/management.log"

	defaultSingleAccModeDomain = "netbird.selfhosted"
)

var defaultWSProxyAddr = fmt.Sprintf("127.0.0.1:%d", server.ManagementLegacyPort)
