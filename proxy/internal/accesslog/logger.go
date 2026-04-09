package accesslog

import (
	"context"
	"maps"
	"net/netip"
	"sync"
	"sync/atomic"
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

	// denyCooldown is the min interval between deny log entries per service+reason
	// to prevent flooding from denied connections (e.g. UDP packets from blocked IPs).
	denyCooldown = 10 * time.Second

	// maxDenyBuckets caps tracked deny rate-limit entries to bound memory under DDoS.
	maxDenyBuckets = 10000

	// maxLogWorkers caps concurrent gRPC send goroutines.
	maxLogWorkers = 4096
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

// denyBucketKey identifies a rate-limited deny log stream.
type denyBucketKey struct {
	ServiceID types.ServiceID
	Reason    string
}

// denyBucket tracks rate-limited deny log entries.
type denyBucket struct {
	lastLogged time.Time
	suppressed int64
}

// Logger sends access log entries to the management server via gRPC.
type Logger struct {
	client         gRPCClient
	logger         *log.Logger
	trustedProxies []netip.Prefix

	usageMux    sync.Mutex
	domainUsage map[string]*domainUsage

	denyMu      sync.Mutex
	denyBuckets map[denyBucketKey]*denyBucket

	logSem        chan struct{}
	cleanupCancel context.CancelFunc
	dropped       atomic.Int64
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
		denyBuckets:    make(map[denyBucketKey]*denyBucket),
		logSem:         make(chan struct{}, maxLogWorkers),
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
	ServiceID     types.ServiceID
	Host          string
	Path          string
	DurationMs    int64
	Method        string
	ResponseCode  int32
	SourceIP      netip.Addr
	AuthMechanism string
	UserID        string
	AuthSuccess   bool
	BytesUpload   int64
	BytesDownload int64
	Protocol      Protocol
	Metadata      map[string]string
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
	// DenyReason, when non-empty, indicates the connection was denied.
	// Values match the HTTP auth mechanism strings: "ip_restricted",
	// "country_restricted", "geo_unavailable", "crowdsec_ban", etc.
	DenyReason string
	// Metadata carries extra context about the connection (e.g. CrowdSec verdict).
	Metadata map[string]string
}

// LogL4 sends an access log entry for a layer-4 connection (TCP or UDP).
// The call is non-blocking: the gRPC send happens in a background goroutine.
func (l *Logger) LogL4(entry L4Entry) {
	le := logEntry{
		ID:            xid.New().String(),
		AccountID:     entry.AccountID,
		ServiceID:     entry.ServiceID,
		Protocol:      entry.Protocol,
		Host:          entry.Host,
		SourceIP:      entry.SourceIP,
		DurationMs:    entry.DurationMs,
		BytesUpload:   entry.BytesUpload,
		BytesDownload: entry.BytesDownload,
		Metadata:      maps.Clone(entry.Metadata),
	}
	if entry.DenyReason != "" {
		if !l.allowDenyLog(entry.ServiceID, entry.DenyReason) {
			return
		}
		le.AuthMechanism = entry.DenyReason
		le.AuthSuccess = false
	}
	l.log(le)
	l.trackUsage(entry.Host, entry.BytesUpload+entry.BytesDownload)
}

// allowDenyLog rate-limits deny log entries per service+reason combination.
func (l *Logger) allowDenyLog(serviceID types.ServiceID, reason string) bool {
	key := denyBucketKey{ServiceID: serviceID, Reason: reason}
	now := time.Now()

	l.denyMu.Lock()
	defer l.denyMu.Unlock()

	b, ok := l.denyBuckets[key]
	if !ok {
		if len(l.denyBuckets) >= maxDenyBuckets {
			return false
		}
		l.denyBuckets[key] = &denyBucket{lastLogged: now}
		return true
	}

	if now.Sub(b.lastLogged) >= denyCooldown {
		if b.suppressed > 0 {
			l.logger.Debugf("access restriction: suppressed %d deny log entries for %s (%s)", b.suppressed, serviceID, reason)
		}
		b.lastLogged = now
		b.suppressed = 0
		return true
	}

	b.suppressed++
	return false
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
	now := timestamppb.Now()
	select {
	case l.logSem <- struct{}{}:
	default:
		total := l.dropped.Add(1)
		l.logger.Debugf("access log send dropped: worker limit reached (total dropped: %d)", total)
		return
	}
	go func() {
		defer func() { <-l.logSem }()
		logCtx, cancel := context.WithTimeout(context.Background(), logSendTimeout)
		defer cancel()
		// Only OIDC sessions have a meaningful user identity.
		if entry.AuthMechanism != auth.MethodOIDC.String() {
			entry.UserID = ""
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
				ServiceId:     string(entry.ServiceID),
				Host:          entry.Host,
				Path:          entry.Path,
				DurationMs:    entry.DurationMs,
				Method:        entry.Method,
				ResponseCode:  entry.ResponseCode,
				SourceIp:      sourceIP,
				AuthMechanism: entry.AuthMechanism,
				UserId:        entry.UserID,
				AuthSuccess:   entry.AuthSuccess,
				BytesUpload:   entry.BytesUpload,
				BytesDownload: entry.BytesDownload,
				Protocol:      string(entry.Protocol),
				Metadata:      entry.Metadata,
			},
		}); err != nil {
			l.logger.WithFields(log.Fields{
				"service_id":     entry.ServiceID,
				"host":           entry.Host,
				"path":           entry.Path,
				"duration":       entry.DurationMs,
				"method":         entry.Method,
				"response_code":  entry.ResponseCode,
				"source_ip":      sourceIP,
				"auth_mechanism": entry.AuthMechanism,
				"user_id":        entry.UserID,
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

// cleanupStaleUsage removes usage and deny-rate-limit entries that have been inactive.
func (l *Logger) cleanupStaleUsage(ctx context.Context) {
	ticker := time.NewTicker(usageCleanupPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			l.cleanupDomainUsage(now)
			l.cleanupDenyBuckets(now)
		}
	}
}

func (l *Logger) cleanupDomainUsage(now time.Time) {
	l.usageMux.Lock()
	defer l.usageMux.Unlock()

	removed := 0
	for domain, usage := range l.domainUsage {
		if now.Sub(usage.lastActivity) > usageInactiveWindow {
			delete(l.domainUsage, domain)
			removed++
		}
	}
	if removed > 0 {
		l.logger.Debugf("cleaned up %d stale domain usage entries", removed)
	}
}

func (l *Logger) cleanupDenyBuckets(now time.Time) {
	l.denyMu.Lock()
	defer l.denyMu.Unlock()

	removed := 0
	for key, bucket := range l.denyBuckets {
		if now.Sub(bucket.lastLogged) > usageInactiveWindow {
			delete(l.denyBuckets, key)
			removed++
		}
	}
	if removed > 0 {
		l.logger.Debugf("cleaned up %d stale deny rate-limit entries", removed)
	}
}
