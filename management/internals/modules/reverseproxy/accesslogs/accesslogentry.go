package accesslogs

import (
	"maps"
	"net"
	"net/netip"
	"time"

	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// AccessLogProtocol identifies the transport protocol of an access log entry.
type AccessLogProtocol string

const (
	AccessLogProtocolHTTP AccessLogProtocol = "http"
	AccessLogProtocolTCP  AccessLogProtocol = "tcp"
	AccessLogProtocolUDP  AccessLogProtocol = "udp"
)

type AccessLogEntry struct {
	ID              string        `gorm:"primaryKey"`
	AccountID       string        `gorm:"index"`
	ServiceID       string        `gorm:"index"`
	Timestamp       time.Time     `gorm:"index"`
	GeoLocation     peer.Location `gorm:"embedded;embeddedPrefix:location_"`
	SubdivisionCode string
	Method          string        `gorm:"index"`
	Host            string        `gorm:"index"`
	Path            string        `gorm:"index"`
	Duration        time.Duration `gorm:"index"`
	StatusCode      int           `gorm:"index"`
	Reason          string
	UserId          string            `gorm:"index"`
	AuthMethodUsed  string            `gorm:"index"`
	BytesUpload     int64             `gorm:"index"`
	BytesDownload   int64             `gorm:"index"`
	Protocol        AccessLogProtocol `gorm:"index"`
	Metadata        map[string]string `gorm:"serializer:json"`
}

// FromProto creates an AccessLogEntry from a proto.AccessLog
func (a *AccessLogEntry) FromProto(serviceLog *proto.AccessLog) {
	a.ID = serviceLog.GetLogId()
	a.ServiceID = serviceLog.GetServiceId()
	a.Timestamp = serviceLog.GetTimestamp().AsTime()
	a.Method = serviceLog.GetMethod()
	a.Host = serviceLog.GetHost()
	a.Path = serviceLog.GetPath()
	a.Duration = time.Duration(serviceLog.GetDurationMs()) * time.Millisecond
	a.StatusCode = int(serviceLog.GetResponseCode())
	a.UserId = serviceLog.GetUserId()
	a.AuthMethodUsed = serviceLog.GetAuthMechanism()
	a.AccountID = serviceLog.GetAccountId()
	a.BytesUpload = serviceLog.GetBytesUpload()
	a.BytesDownload = serviceLog.GetBytesDownload()
	a.Protocol = AccessLogProtocol(serviceLog.GetProtocol())
	a.Metadata = maps.Clone(serviceLog.GetMetadata())

	if sourceIP := serviceLog.GetSourceIp(); sourceIP != "" {
		if addr, err := netip.ParseAddr(sourceIP); err == nil {
			addr = addr.Unmap()
			a.GeoLocation.ConnectionIP = net.IP(addr.AsSlice())
		}
	}

	// Only set reason for HTTP entries. L4 entries have no auth or status code.
	if a.Protocol == "" || a.Protocol == AccessLogProtocolHTTP {
		if !serviceLog.GetAuthSuccess() {
			a.Reason = "Authentication failed"
		} else if serviceLog.GetResponseCode() >= 400 {
			a.Reason = "Request failed"
		}
	}
}

// ToAPIResponse converts an AccessLogEntry to the API ProxyAccessLog type
func (a *AccessLogEntry) ToAPIResponse() *api.ProxyAccessLog {
	var sourceIP *string
	if a.GeoLocation.ConnectionIP != nil {
		ip := a.GeoLocation.ConnectionIP.String()
		sourceIP = &ip
	}

	var reason *string
	if a.Reason != "" {
		reason = &a.Reason
	}

	var userID *string
	if a.UserId != "" {
		userID = &a.UserId
	}

	var authMethod *string
	if a.AuthMethodUsed != "" {
		authMethod = &a.AuthMethodUsed
	}

	var countryCode *string
	if a.GeoLocation.CountryCode != "" {
		countryCode = &a.GeoLocation.CountryCode
	}

	var cityName *string
	if a.GeoLocation.CityName != "" {
		cityName = &a.GeoLocation.CityName
	}

	var subdivisionCode *string
	if a.SubdivisionCode != "" {
		subdivisionCode = &a.SubdivisionCode
	}

	var protocol *string
	if a.Protocol != "" {
		p := string(a.Protocol)
		protocol = &p
	}

	var metadata *map[string]string
	if len(a.Metadata) > 0 {
		metadata = &a.Metadata
	}

	return &api.ProxyAccessLog{
		Id:              a.ID,
		ServiceId:       a.ServiceID,
		Timestamp:       a.Timestamp,
		Method:          a.Method,
		Host:            a.Host,
		Path:            a.Path,
		DurationMs:      int(a.Duration.Milliseconds()),
		StatusCode:      a.StatusCode,
		SourceIp:        sourceIP,
		Reason:          reason,
		UserId:          userID,
		AuthMethodUsed:  authMethod,
		CountryCode:     countryCode,
		CityName:        cityName,
		SubdivisionCode: subdivisionCode,
		BytesUpload:     a.BytesUpload,
		BytesDownload:   a.BytesDownload,
		Protocol:        protocol,
		Metadata:        metadata,
	}
}
