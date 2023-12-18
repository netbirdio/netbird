package listener

// NetworkChangeListener is a callback interface for mobile system
type NetworkChangeListener interface {
	// OnNetworkChanged invoke when network settings has been changed
	OnNetworkChanged(string)
	SetInterfaceIP(string)
}
