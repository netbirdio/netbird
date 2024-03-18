package account

type ExtraSettings struct {
	// PeerApprovalEnabled enables or disables the need for peers bo be approved by an administrator
	PeerApprovalEnabled bool

	// IntegratedValidatorGroups list of group IDs to be used with integrated approval configurations
	IntegratedValidatorGroups []string `gorm:"serializer:json"`
}

// Copy copies the ExtraSettings struct
func (e *ExtraSettings) Copy() *ExtraSettings {
	var cpGroup []string

	return &ExtraSettings{
		PeerApprovalEnabled:       e.PeerApprovalEnabled,
		IntegratedValidatorGroups: append(cpGroup, e.IntegratedValidatorGroups...),
	}
}
