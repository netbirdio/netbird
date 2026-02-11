package accesslogs

import (
	"net"
	"net/netip"
	"time"

	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type AccessLogEntry struct {
	ID             string        `gorm:"primaryKey"`
	AccountID      string        `gorm:"index"`
	ProxyID        string        `gorm:"index"`
	Timestamp      time.Time     `gorm:"index"`
	GeoLocation    peer.Location `gorm:"embedded;embeddedPrefix:location_"`
	Method         string        `gorm:"index"`
	Host           string        `gorm:"index"`
	Path           string        `gorm:"index"`
	Duration       time.Duration `gorm:"index"`
	StatusCode     int           `gorm:"index"`
	Reason         string
	UserId         string `gorm:"index"`
	AuthMethodUsed string `gorm:"index"`
}

// FromProto creates an AccessLogEntry from a proto.AccessLog
func (a *AccessLogEntry) FromProto(proxyLog *proto.AccessLog) {
	a.ID = proxyLog.GetLogId()
	a.ProxyID = proxyLog.GetServiceId()
	a.Timestamp = proxyLog.GetTimestamp().AsTime()
	a.Method = proxyLog.GetMethod()
	a.Host = proxyLog.GetHost()
	a.Path = proxyLog.GetPath()
	a.Duration = time.Duration(proxyLog.GetDurationMs()) * time.Millisecond
	a.StatusCode = int(proxyLog.GetResponseCode())
	a.UserId = proxyLog.GetUserId()
	a.AuthMethodUsed = proxyLog.GetAuthMechanism()
	a.AccountID = proxyLog.GetAccountId()

	if sourceIP := proxyLog.GetSourceIp(); sourceIP != "" {
		if ip, err := netip.ParseAddr(sourceIP); err == nil {
			a.GeoLocation.ConnectionIP = net.IP(ip.AsSlice())
		}
	}

	if !proxyLog.GetAuthSuccess() {
		a.Reason = "Authentication failed"
	} else if proxyLog.GetResponseCode() >= 400 {
		a.Reason = "Request failed"
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

	return &api.ProxyAccessLog{
		Id:             a.ID,
		ProxyId:        a.ProxyID,
		Timestamp:      a.Timestamp,
		Method:         a.Method,
		Host:           a.Host,
		Path:           a.Path,
		DurationMs:     int(a.Duration.Milliseconds()),
		StatusCode:     a.StatusCode,
		SourceIp:       sourceIP,
		Reason:         reason,
		UserId:         userID,
		AuthMethodUsed: authMethod,
		CountryCode:    countryCode,
		CityName:       cityName,
	}
}
