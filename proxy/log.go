package proxy

import (
	stdlog "log"

	log "github.com/sirupsen/logrus"
)

const (
	// HTTP server type identifiers for logging
	logtagFieldHTTPServer = "http-server"
	logtagValueHTTPS      = "https"
	logtagValueACME       = "acme"
	logtagValueDebug      = "debug"
)

// newHTTPServerLogger creates a standard library logger that writes to logrus
// with the specified server type field.
func newHTTPServerLogger(logger *log.Logger, serverType string) *stdlog.Logger {
	return stdlog.New(logger.WithField(logtagFieldHTTPServer, serverType).WriterLevel(log.WarnLevel), "", 0)
}
