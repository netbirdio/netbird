package accesslog

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	requestThreshold    = 10000              // Log every 10k requests
	bytesThreshold      = 1024 * 1024 * 1024 // Log every 1GB
	usageCleanupPeriod  = 1 * time.Hour      // Clean up stale counters every hour
	usageInactiveWindow = 24 * time.Hour     // Consider domain inactive if no traffic for 24 hours
	logSendTimeout      = 10 * time.Second
)

type domainUsage struct {
	requestCount     int64
	requestStartTime time.Time

	bytesTransferred int64
	bytesStartTime   time.Time

	lastActivity time.Time // Track last activity for cleanup
}

type gRPCClient interface {
	SendAccessLog(ctx context.Context, in *proto.SendAccessLogRequest, opts ...grpc.CallOption) (*proto.SendAccessLogResponse, error)
}

// Logger sends access log entries to the management server via gRPC.
type Logger struct {
	client         gRPCClient
	logger         *log.Logger
	trustedProxies []netip.Prefix

	usageMux    sync.Mutex
	domainUsage map[string]*domainUsage

	cleanupCancel context.CancelFunc
}

// NewLogger creates a new access log Logger. The trustedProxies parameter
// configures which upstream proxy IP ranges are trusted for extracting
// the real client IP from X-Forwarded-For headers.
func NewLogger(client gRPCClient, logger *log.Logger, trustedProxies []netip.Prefix) *Logger {
	if logger == nil {
		logger = log.StandardLogger()
	}

	ctx, cancel := context.WithCancel(context.Background())
	l := &Logger{
		client:         client,
		logger:         logger,
		trustedProxies: trustedProxies,
		domainUsage:    make(map[string]*domainUsage),
		cleanupCancel:  cancel,
	}

	// Start background cleanup routine
	go l.cleanupStaleUsage(ctx)

	return l
}

// Close stops the cleanup routine. Should be called during graceful shutdown.
func (l *Logger) Close() {
	if l.cleanupCancel != nil {
		l.cleanupCancel()
	}
}

type logEntry struct {
	ID            string
	AccountID     types.AccountID
	ServiceId     types.ServiceID
	Host          string
	Path          string
	DurationMs    int64
	Method        string
	ResponseCode  int32
	SourceIP      netip.Addr
	AuthMechanism string
	UserId        string
	AuthSuccess   bool
	BytesUpload   int64
	BytesDownload int64
	Protocol      Protocol
}

// Protocol identifies the transport protocol of an access log entry.
type Protocol string

const (
	ProtocolHTTP Protocol = "http"
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
	ProtocolTLS  Protocol = "tls"
)

// L4Entry holds the data for a layer-4 (TCP/UDP) access log entry.
type L4Entry struct {
	AccountID     types.AccountID
	ServiceID     types.ServiceID
	Protocol      Protocol
	Host          string // SNI hostname or listen address
	SourceIP      netip.Addr
	DurationMs    int64
	BytesUpload   int64
	BytesDownload int64
}

// LogL4 sends an access log entry for a layer-4 connection (TCP or UDP).
// The call is non-blocking: the gRPC send happens in a background goroutine.
func (l *Logger) LogL4(entry L4Entry) {
	le := logEntry{
		ID:            xid.New().String(),
		AccountID:     entry.AccountID,
		ServiceId:     entry.ServiceID,
		Protocol:      entry.Protocol,
		Host:          entry.Host,
		SourceIP:      entry.SourceIP,
		DurationMs:    entry.DurationMs,
		BytesUpload:   entry.BytesUpload,
		BytesDownload: entry.BytesDownload,
	}
	l.log(le)
	l.trackUsage(entry.Host, entry.BytesUpload+entry.BytesDownload)
}

func (l *Logger) log(entry logEntry) {
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
		logCtx, cancel := context.WithTimeout(context.Background(), logSendTimeout)
		defer cancel()
		if entry.AuthMechanism != auth.MethodOIDC.String() {
			entry.UserId = ""
		}

		var sourceIP string
		if entry.SourceIP.IsValid() {
			sourceIP = entry.SourceIP.String()
		}

		if _, err := l.client.SendAccessLog(logCtx, &proto.SendAccessLogRequest{
			Log: &proto.AccessLog{
				LogId:         entry.ID,
				AccountId:     string(entry.AccountID),
				Timestamp:     now,
				ServiceId:     string(entry.ServiceId),
				Host:          entry.Host,
				Path:          entry.Path,
				DurationMs:    entry.DurationMs,
				Method:        entry.Method,
				ResponseCode:  entry.ResponseCode,
				SourceIp:      sourceIP,
				AuthMechanism: entry.AuthMechanism,
				UserId:        entry.UserId,
				AuthSuccess:   entry.AuthSuccess,
				BytesUpload:   entry.BytesUpload,
				BytesDownload: entry.BytesDownload,
				Protocol:      string(entry.Protocol),
			},
		}); err != nil {
			l.logger.WithFields(log.Fields{
				"service_id":     entry.ServiceId,
				"host":           entry.Host,
				"path":           entry.Path,
				"duration":       entry.DurationMs,
				"method":         entry.Method,
				"response_code":  entry.ResponseCode,
				"source_ip":      sourceIP,
				"auth_mechanism": entry.AuthMechanism,
				"user_id":        entry.UserId,
				"auth_success":   entry.AuthSuccess,
				"error":          err,
			}).Error("Error sending access log on gRPC connection")
		}
	}()
}

// trackUsage records request and byte counts per domain, logging when thresholds are hit.
func (l *Logger) trackUsage(domain string, bytesTransferred int64) {
	if domain == "" {
		return
	}

	l.usageMux.Lock()
	defer l.usageMux.Unlock()

	now := time.Now()
	usage, exists := l.domainUsage[domain]
	if !exists {
		usage = &domainUsage{
			requestStartTime: now,
			bytesStartTime:   now,
			lastActivity:     now,
		}
		l.domainUsage[domain] = usage
	}

	usage.lastActivity = now

	usage.requestCount++
	if usage.requestCount >= requestThreshold {
		elapsed := time.Since(usage.requestStartTime)
		l.logger.WithFields(log.Fields{
			"domain":   domain,
			"requests": usage.requestCount,
			"duration": elapsed.String(),
		}).Infof("domain %s had %d requests over %s", domain, usage.requestCount, elapsed)

		usage.requestCount = 0
		usage.requestStartTime = now
	}

	usage.bytesTransferred += bytesTransferred
	if usage.bytesTransferred >= bytesThreshold {
		elapsed := time.Since(usage.bytesStartTime)
		bytesInGB := float64(usage.bytesTransferred) / (1024 * 1024 * 1024)
		l.logger.WithFields(log.Fields{
			"domain":   domain,
			"bytes":    usage.bytesTransferred,
			"bytes_gb": bytesInGB,
			"duration": elapsed.String(),
		}).Infof("domain %s transferred %.2f GB over %s", domain, bytesInGB, elapsed)

		usage.bytesTransferred = 0
		usage.bytesStartTime = now
	}
}

// cleanupStaleUsage removes usage entries for domains that have been inactive.
func (l *Logger) cleanupStaleUsage(ctx context.Context) {
	ticker := time.NewTicker(usageCleanupPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.usageMux.Lock()
			now := time.Now()
			removed := 0
			for domain, usage := range l.domainUsage {
				if now.Sub(usage.lastActivity) > usageInactiveWindow {
					delete(l.domainUsage, domain)
					removed++
				}
			}
			l.usageMux.Unlock()

			if removed > 0 {
				l.logger.Debugf("cleaned up %d stale domain usage entries", removed)
			}
		}
	}
}
