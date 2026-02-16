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
	ServiceID      string        `gorm:"index"`
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

	if sourceIP := serviceLog.GetSourceIp(); sourceIP != "" {
		if ip, err := netip.ParseAddr(sourceIP); err == nil {
			a.GeoLocation.ConnectionIP = net.IP(ip.AsSlice())
		}
	}

	if !serviceLog.GetAuthSuccess() {
		a.Reason = "Authentication failed"
	} else if serviceLog.GetResponseCode() >= 400 {
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
		ServiceId:      a.ServiceID,
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
