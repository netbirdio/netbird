package accesslog

import (
	"context"
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type gRPCClient interface {
	SendAccessLog(ctx context.Context, in *proto.SendAccessLogRequest, opts ...grpc.CallOption) (*proto.SendAccessLogResponse, error)
}

// Logger sends access log entries to the management server via gRPC.
type Logger struct {
	client         gRPCClient
	logger         *log.Logger
	trustedProxies []netip.Prefix
}

// NewLogger creates a new access log Logger. The trustedProxies parameter
// configures which upstream proxy IP ranges are trusted for extracting
// the real client IP from X-Forwarded-For headers.
func NewLogger(client gRPCClient, logger *log.Logger, trustedProxies []netip.Prefix) *Logger {
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &Logger{
		client:         client,
		logger:         logger,
		trustedProxies: trustedProxies,
	}
}

type logEntry struct {
	ID            string
	AccountID     string
	ServiceId     string
	Host          string
	Path          string
	DurationMs    int64
	Method        string
	ResponseCode  int32
	SourceIp      string
	AuthMechanism string
	UserId        string
	AuthSuccess   bool
}

func (l *Logger) log(ctx context.Context, entry logEntry) {
	// Fire off the log request in a separate routine.
	// This increases the possibility of losing a log message
	// (although it should still get logged in the event of an error),
	// but it will reduce latency returning the request in the
	// middleware.
	// There is also a chance that log messages will arrive at
	// the server out of order; however, the timestamp should
	// allow for resolving that on the server.
	now := timestamppb.Now() // Grab the timestamp before launching the goroutine to try to prevent weird timing issues. This is probably unnecessary.
	go func() {
		logCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if entry.AuthMechanism != auth.MethodOIDC.String() {
			entry.UserId = ""
		}
		if _, err := l.client.SendAccessLog(logCtx, &proto.SendAccessLogRequest{
			Log: &proto.AccessLog{
				LogId:         entry.ID,
				AccountId:     entry.AccountID,
				Timestamp:     now,
				ServiceId:     entry.ServiceId,
				Host:          entry.Host,
				Path:          entry.Path,
				DurationMs:    entry.DurationMs,
				Method:        entry.Method,
				ResponseCode:  entry.ResponseCode,
				SourceIp:      entry.SourceIp,
				AuthMechanism: entry.AuthMechanism,
				UserId:        entry.UserId,
				AuthSuccess:   entry.AuthSuccess,
			},
		}); err != nil {
			// If it fails to send on the gRPC connection, then at least log it to the error log.
			l.logger.WithFields(log.Fields{
				"service_id":     entry.ServiceId,
				"host":           entry.Host,
				"path":           entry.Path,
				"duration":       entry.DurationMs,
				"method":         entry.Method,
				"response_code":  entry.ResponseCode,
				"source_ip":      entry.SourceIp,
				"auth_mechanism": entry.AuthMechanism,
				"user_id":        entry.UserId,
				"auth_success":   entry.AuthSuccess,
				"error":          err,
			}).Error("Error sending access log on gRPC connection")
		}
	}()
}
