package modules

type Module string

const (
	Networks    Module = "networks"
	Peers       Module = "peers"
	Groups      Module = "groups"
	Settings    Module = "settings"
	Accounts    Module = "accounts"
	Dns         Module = "dns"
	Nameservers Module = "nameservers"
	Events      Module = "events"
	Policies    Module = "policies"
	Routes      Module = "routes"
	Users       Module = "users"
	SetupKeys   Module = "setup_keys"
	Pats        Module = "pats"
)
