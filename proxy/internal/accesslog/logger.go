package accesslog

import (
	"context"
	"log/slog"

	"github.com/netbirdio/netbird/shared/management/proto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type gRPCClient interface {
	SendAccessLog(ctx context.Context, in *proto.SendAccessLogRequest, opts ...grpc.CallOption) (*proto.SendAccessLogResponse, error)
}

type errorLogger interface {
	ErrorContext(ctx context.Context, msg string, args ...any)
}

type Logger struct {
	client   gRPCClient
	errorLog errorLogger
}

func NewLogger(client gRPCClient, errorLog errorLogger) *Logger {
	if errorLog == nil {
		errorLog = slog.New(slog.DiscardHandler)
	}
	return &Logger{
		client:   client,
		errorLog: errorLog,
	}
}

type logEntry struct {
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

func (l *Logger) log(ctx context.Context, log logEntry) {
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
		if _, err := l.client.SendAccessLog(ctx, &proto.SendAccessLogRequest{
			Log: &proto.AccessLog{
				Timestamp:     now,
				ServiceId:     log.ServiceId,
				Host:          log.Host,
				Path:          log.Path,
				DurationMs:    log.DurationMs,
				Method:        log.Method,
				ResponseCode:  log.ResponseCode,
				SourceIp:      log.SourceIp,
				AuthMechanism: log.AuthMechanism,
				UserId:        log.UserId,
				AuthSuccess:   log.AuthSuccess,
			},
		}); err != nil {
			// If it fails to send on the gRPC connection, then at least log it to the error log.
			l.errorLog.ErrorContext(ctx, "Error sending access log on gRPC connection",
				"service_id", log.ServiceId,
				"host", log.Host,
				"path", log.Path,
				"duration", log.DurationMs,
				"method", log.Method,
				"response_code", log.ResponseCode,
				"source_ip", log.SourceIp,
				"auth_mechanism", log.AuthMechanism,
				"user_id", log.UserId,
				"auth_success", log.AuthSuccess,
				"error", err)
		}
	}()
}
