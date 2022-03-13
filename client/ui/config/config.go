package config

import (
	"os"
	"runtime"
)

// ClientConfig basic settings for the UI application.
type ClientConfig struct {
	configPath string
	logFile    string
	daemonAddr string
}

// Config object with default settings.
//
// We are creating this package to extract utility functions from the cmd package
// reading and parsing the configurations for the client should be done here
func Config() *ClientConfig {
	defaultConfigPath := "/etc/wiretrustee/config.json"
	defaultLogFile := "/var/log/wiretrustee/client.log"
	if runtime.GOOS == "windows" {
		defaultConfigPath = os.Getenv("PROGRAMDATA") + "\\Wiretrustee\\" + "config.json"
		defaultLogFile = os.Getenv("PROGRAMDATA") + "\\Wiretrustee\\" + "client.log"
	}

	defaultDaemonAddr := "unix:///var/run/wiretrustee.sock"
	if runtime.GOOS == "windows" {
		defaultDaemonAddr = "tcp://127.0.0.1:41731"
	}
	return &ClientConfig{
		configPath: defaultConfigPath,
		logFile:    defaultLogFile,
		daemonAddr: defaultDaemonAddr,
	}
}

// DaemonAddr of the gRPC API.
func (c *ClientConfig) DaemonAddr() string {
	return c.daemonAddr
}

// LogFile path.
func (c *ClientConfig) LogFile() string {
	return c.logFile
}
