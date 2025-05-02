package types

import (
	"fmt"

	"github.com/miekg/dns"
)

type HandlerID string

type RecordKey string

// BuildRecordKey consistently generates a key: name_class_type
func BuildRecordKey(name string, class, qType uint16) RecordKey {
	return RecordKey(fmt.Sprintf("%s_%d_%d", dns.Fqdn(name), class, qType))
}

type RegistrationMap map[RecordKey]struct{}
