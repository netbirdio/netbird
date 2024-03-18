package types

// CustomZone represents a custom zone to be resolved by the dns server
type CustomZone struct {
	// Domain is the zone's domain
	Domain string
	// Records custom zone records
	Records []SimpleRecord
}
