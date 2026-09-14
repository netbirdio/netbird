package ipcauth

const servicePath = "/daemon.DaemonService/"

// Request is what a rule decides on: the authorization plus the state and the
// message, which only the gate needs.
type Request struct {
	Identity Identity
	State    DaemonState
	Level    AuthzLevel
	Target   string
	Method   string
	Msg      any
}

// Rule is an additional constraint beyond the method's level, for example
// checking permissions on a field of a message. Every rule on a method must pass.
type Rule func(Request) error

// The generated getters the profile RPCs expose.
type handleTargeted interface{ GetHandle() string }
type profileTargeted interface{ GetProfileName() string }

// targetProfile returns the profile a request names, and whether it carries a
// target field at all. Requests with no target act on the active profile.
func targetProfile(msg any) (string, bool) {
	switch m := msg.(type) {
	case handleTargeted:
		return m.GetHandle(), true
	case profileTargeted:
		return m.GetProfileName(), true
	default:
		return "", false
	}
}

// MethodPolicy is what a method requires to be authorized and then handled.
type MethodPolicy struct {
	Level          AuthzLevel
	Rules          []Rule
	Audit          bool
	TargetsProfile bool

	// Action and Command turn a privilege denial into guidance the caller can
	// act on. Action reads as the subject of a sentence ("claiming a profile"),
	// Command is the same operation run with the privileges it needs. Only read
	// when Level is AuthzLevelPrivileged, the one denial a caller can fix by
	// running as somebody else.
	Action  string
	Command string
}

// methodPolicies is the complete authorization surface. Every RPC on
// DaemonService appears here exactly once.
var methodPolicies = map[string]MethodPolicy{
	// Any identified caller.
	servicePath + "Status":           {Level: AuthzLevelIdentified, Rules: []Rule{RequireHolderForFullStatus}, Action: "reading status"},
	servicePath + "AddProfile":       {Level: AuthzLevelIdentified, Audit: true, Action: "adding a profile"},
	servicePath + "ListProfiles":     {Level: AuthzLevelIdentified, Action: "listing profiles"},
	servicePath + "GetActiveProfile": {Level: AuthzLevelIdentified, Action: "reading the active profile"},
	servicePath + "GetFeatures":      {Level: AuthzLevelIdentified, Action: "reading feature flags"},
	servicePath + "WailsUIReady":     {Level: AuthzLevelIdentified, Action: "starting the UI"},
<<<<<<< HEAD
=======

	// Pending flows: bound to the principal that started them, at any level.
	servicePath + "WaitSSOLogin":          {Level: AuthzLevelIdentified, Rules: []Rule{RequireFlowInitiator}, Audit: true, Action: "waiting for the login to finish"},
	servicePath + "WaitJWTToken":          {Level: AuthzLevelIdentified, Rules: []Rule{RequireFlowInitiator}, Audit: true, Action: "waiting for the token"},
	servicePath + "WaitExtendAuthSession": {Level: AuthzLevelIdentified, Rules: []Rule{RequireFlowInitiator}, Action: "extending the session"},
>>>>>>> 38337642c ((WIP) Add readable errors for AuthzLevels)

	// Owner of the profile the request names.
	servicePath + "GetConfig":     {Level: AuthzLevelProfileOwner, TargetsProfile: true, Audit: true, Action: "reading the profile configuration"},
	servicePath + "SetConfig":     {Level: AuthzLevelProfileOwner, TargetsProfile: true, Audit: true, Action: "changing the profile configuration"},
	servicePath + "Login":         {Level: AuthzLevelSessionHolder, TargetsProfile: true, Audit: true, Action: "logging in"},
	servicePath + "Logout":        {Level: AuthzLevelProfileOwner, TargetsProfile: true, Audit: true, Action: "logging out"},
	servicePath + "RenameProfile": {Level: AuthzLevelProfileOwner, TargetsProfile: true, Action: "renaming a profile"},
	servicePath + "RemoveProfile": {Level: AuthzLevelProfileOwner, TargetsProfile: true, Audit: true, Action: "removing a profile"},
	servicePath + "SwitchProfile": {Level: AuthzLevelSessionHolder, TargetsProfile: true, Audit: true, Action: "switching profile"},
<<<<<<< HEAD

	// Owner of the active profile, which is what an empty target resolves to.
	servicePath + "WaitSSOLogin":          {Level: AuthzLevelProfileOwner, Audit: true, Action: "waiting for the login to finish"},
	servicePath + "WaitJWTToken":          {Level: AuthzLevelProfileOwner, Audit: true, Action: "waiting for the token"},
	servicePath + "WaitExtendAuthSession": {Level: AuthzLevelProfileOwner, Action: "extending the session"},
=======
>>>>>>> 38337642c ((WIP) Add readable errors for AuthzLevels)

	// Owner of some profile
	servicePath + "GetLogLevel":        {Level: AuthzLevelProfileOwner, Action: "reading the log level"},
	servicePath + "ListStates":         {Level: AuthzLevelProfileOwner, Action: "listing stored state"},
	servicePath + "GetInstallerResult": {Level: AuthzLevelProfileOwner, Action: "reading the installer result"},

	// Session holder: the live engine and everything daemon-wide.
	servicePath + "Up":                         {Level: AuthzLevelSessionHolder, TargetsProfile: true, Audit: true, Action: "connecting"},
	servicePath + "Down":                       {Level: AuthzLevelSessionHolder, Audit: true, Action: "disconnecting"},
	servicePath + "SubscribeStatus":            {Level: AuthzLevelSessionHolder, Action: "following status"},
	servicePath + "SubscribeEvents":            {Level: AuthzLevelSessionHolder, Action: "following events"},
	servicePath + "GetEvents":                  {Level: AuthzLevelSessionHolder, Action: "reading events"},
	servicePath + "ListNetworks":               {Level: AuthzLevelSessionHolder, Action: "listing networks"},
	servicePath + "SelectNetworks":             {Level: AuthzLevelSessionHolder, Audit: true, Action: "selecting networks"},
	servicePath + "DeselectNetworks":           {Level: AuthzLevelSessionHolder, Audit: true, Action: "deselecting networks"},
	servicePath + "ForwardingRules":            {Level: AuthzLevelSessionHolder, Action: "listing forwarding rules"},
	servicePath + "ExposeService":              {Level: AuthzLevelSessionHolder, Audit: true, Action: "exposing a service"},
	servicePath + "GetPeerSSHHostKey":          {Level: AuthzLevelSessionHolder, Action: "reading a peer SSH host key"},
	servicePath + "RequestJWTAuth":             {Level: AuthzLevelSessionHolder, Audit: true, Action: "starting authentication"},
	servicePath + "RequestExtendAuthSession":   {Level: AuthzLevelSessionHolder, Action: "extending the session"},
	servicePath + "DismissSessionWarning":      {Level: AuthzLevelSessionHolder, Action: "dismissing the session warning"},
	servicePath + "DebugBundle":                {Level: AuthzLevelSessionHolder, Audit: true, Action: "creating a debug bundle"},
	servicePath + "SetLogLevel":                {Level: AuthzLevelSessionHolder, Action: "changing the log level"},
	servicePath + "SetSyncResponsePersistence": {Level: AuthzLevelSessionHolder, Action: "changing sync persistence"},
	servicePath + "StartCapture":               {Level: AuthzLevelSessionHolder, Audit: true, Action: "starting a packet capture"},
	servicePath + "StartBundleCapture":         {Level: AuthzLevelSessionHolder, Audit: true, Action: "starting a bundle capture"},
	servicePath + "StopBundleCapture":          {Level: AuthzLevelSessionHolder, Action: "stopping a bundle capture"},
	servicePath + "StartCPUProfile":            {Level: AuthzLevelSessionHolder, Action: "starting a CPU profile"},
	servicePath + "StopCPUProfile":             {Level: AuthzLevelSessionHolder, Action: "stopping a CPU profile"},
	servicePath + "CleanState":                 {Level: AuthzLevelSessionHolder, Audit: true, Action: "clearing stored state"},
	servicePath + "DeleteState":                {Level: AuthzLevelSessionHolder, Audit: true, Action: "deleting stored state"},
	servicePath + "TracePacket":                {Level: AuthzLevelSessionHolder, Action: "tracing a packet"},
	servicePath + "RegisterUILog":              {Level: AuthzLevelSessionHolder, Action: "registering the UI log"},
	servicePath + "TriggerUpdate":              {Level: AuthzLevelSessionHolder, Audit: true, Action: "starting an update"},

	// Root or administrator only. Claiming names an arbitrary principal, so the
	// caller asserts who a profile belongs to. Ownership does not enter it.
	servicePath + "ClaimProfile": {
		Level:          AuthzLevelPrivileged,
		TargetsProfile: true,
		Audit:          true,
		Action:         "claiming a profile",
		Command:        ElevatedCommand("netbird profile claim"),
	},
}

func methodPolicyFor(method string) MethodPolicy {
	if p, ok := methodPolicies[method]; ok {
		return p
	}
	// TODO: reconsider falling back to Privileged rather than direct DENY.
	return MethodPolicy{Level: AuthzLevelPrivileged, Audit: true}
}
