package types

// DNSSettings defines dns settings at the account level
type DNSSettings struct {
	// DisabledManagementGroups groups whose DNS management is disabled
	DisabledManagementGroups []string `gorm:"serializer:json"`
}

// Copy returns a copy of the DNS settings
func (d DNSSettings) Copy() DNSSettings {
	settings := DNSSettings{
		DisabledManagementGroups: make([]string, len(d.DisabledManagementGroups)),
	}
	copy(settings.DisabledManagementGroups, d.DisabledManagementGroups)
	return settings
}
