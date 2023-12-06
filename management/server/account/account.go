package account

type ExtraSettings struct {
	// PeerApprovalEnabled enables or disables the need for peers bo be approved by an administrator
	PeerApprovalEnabled bool
}

// Copy copies the ExtraSettings struct
func (e *ExtraSettings) Copy() *ExtraSettings {
	return &ExtraSettings{
		PeerApprovalEnabled: e.PeerApprovalEnabled,
	}
}
