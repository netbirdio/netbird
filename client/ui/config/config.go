package config

import (
	"os"
	"runtime"
)

type ClientConfig struct {
	configPath string
	logFile    string
	daemonAddr string
}

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

func (c *ClientConfig) DaemonAddr() string {
	return c.daemonAddr
}

func (c *ClientConfig) LogFile() string {
	return c.logFile
}
