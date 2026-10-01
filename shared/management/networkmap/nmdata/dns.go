package nmdata

// SimpleRecord is the slim twin of dns.SimpleRecord.
type SimpleRecord struct {
	Name  string
	Type  int
	Class string
	TTL   int
	RData string
}

// CustomZone is the slim twin of dns.CustomZone.
type CustomZone struct {
	Domain               string
	Records              []SimpleRecord
	SearchDomainDisabled bool
	NonAuthoritative     bool
}
