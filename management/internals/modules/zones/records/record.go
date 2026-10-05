package records

import (
	"errors"
	"net"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

type RecordType string

const (
	RecordTypeA     RecordType = "A"
	RecordTypeAAAA  RecordType = "AAAA"
	RecordTypeCNAME RecordType = "CNAME"
)

type Record struct {
	AccountID string `gorm:"index"`
	ZoneID    string `gorm:"index"`
	ID        string `gorm:"primaryKey"`
	Name      string
	Type      RecordType
	Content   string
	TTL       int
}

func NewRecord(accountID, zoneID, name string, recordType RecordType, content string, ttl int) *Record {
	return &Record{
		ID:        xid.New().String(),
		AccountID: accountID,
		ZoneID:    zoneID,
		Name:      name,
		Type:      recordType,
		Content:   content,
		TTL:       ttl,
	}
}

func (r *Record) ToAPIResponse() *api.DNSRecord {
	recordType := api.DNSRecordType(r.Type)
	return &api.DNSRecord{
		Id:      r.ID,
		Name:    r.Name,
		Type:    recordType,
		Content: r.Content,
		Ttl:     r.TTL,
	}
}

func (r *Record) FromAPIRequest(req *api.DNSRecordRequest) {
	r.Name = req.Name
	r.Type = RecordType(req.Type)
	r.Content = req.Content
	r.TTL = req.Ttl
}

func (r *Record) Validate() error {
	if r.Name == "" {
		return errors.New("record name is required")
	}

	if !domain.IsValidDomain(r.Name) {
		return errors.New("invalid record name format")
	}

	if r.Type == "" {
		return errors.New("record type is required")
	}

	switch r.Type {
	case RecordTypeA:
		if err := validateIPv4(r.Content); err != nil {
			return err
		}
	case RecordTypeAAAA:
		if err := validateIPv6(r.Content); err != nil {
			return err
		}
	case RecordTypeCNAME:
		if !domain.IsValidDomainNoWildcard(r.Content) {
			return errors.New("invalid CNAME target format")
		}
	default:
		return errors.New("invalid record type, must be A, AAAA, or CNAME")
	}

	if r.TTL < 0 {
		return errors.New("TTL cannot be negative")
	}

	return nil
}

func (r *Record) EventMeta(zoneID, zoneName string) map[string]any {
	return map[string]any{
		"name":      r.Name,
		"type":      string(r.Type),
		"content":   r.Content,
		"ttl":       r.TTL,
		"zone_id":   zoneID,
		"zone_name": zoneName,
	}
}

func validateIPv4(content string) error {
	if content == "" {
		return errors.New("A record is required") //nolint:staticcheck
	}
	ip := net.ParseIP(content)
	if ip == nil || ip.To4() == nil {
		return errors.New("A record must be a valid IPv4 address") //nolint:staticcheck
	}
	return nil
}

func validateIPv6(content string) error {
	if content == "" {
		return errors.New("AAAA record is required")
	}
	ip := net.ParseIP(content)
	if ip == nil || ip.To4() != nil {
		return errors.New("AAAA record must be a valid IPv6 address")
	}
	return nil
}
