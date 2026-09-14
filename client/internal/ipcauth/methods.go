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
	servicePath + "Status":           {Level: AuthzLevelIdentified, Rules: []Rule{RequireHolderForFullStatus}},
	servicePath + "AddProfile":       {Level: AuthzLevelIdentified, Audit: true},
	servicePath + "ListProfiles":     {Level: AuthzLevelIdentified},
	servicePath + "GetActiveProfile": {Level: AuthzLevelIdentified},
	servicePath + "GetFeatures":      {Level: AuthzLevelIdentified},
	servicePath + "WailsUIReady":     {Level: AuthzLevelIdentified},

	// Owner of the profile the request names.
	servicePath + "GetConfig":     {Level: AuthzLevelProfileOwner, TargetsProfile: true, Audit: true},
	servicePath + "SetConfig":     {Level: AuthzLevelProfileOwner, TargetsProfile: true, Audit: true},
	servicePath + "Login":         {Level: AuthzLevelSessionHolder, TargetsProfile: true, Audit: true},
	servicePath + "Logout":        {Level: AuthzLevelProfileOwner, TargetsProfile: true, Audit: true},
	servicePath + "RenameProfile": {Level: AuthzLevelProfileOwner, TargetsProfile: true},
	servicePath + "RemoveProfile": {Level: AuthzLevelProfileOwner, TargetsProfile: true, Audit: true},
	servicePath + "SwitchProfile": {Level: AuthzLevelSessionHolder, TargetsProfile: true, Audit: true},

	// Owner of the active profile, which is what an empty target resolves to.
	servicePath + "GetLogLevel":        {Level: AuthzLevelProfileOwner},
	servicePath + "ListStates":         {Level: AuthzLevelProfileOwner},
	servicePath + "GetInstallerResult": {Level: AuthzLevelProfileOwner},

	// Session holder: the live engine and everything daemon-wide. A pending
	// authentication flow belongs to the profile it was started for, so each
	// Wait sits at the level of the RPC that starts it.
	servicePath + "Up":                         {Level: AuthzLevelSessionHolder, TargetsProfile: true, Audit: true},
	servicePath + "Down":                       {Level: AuthzLevelSessionHolder, Audit: true},
	servicePath + "SubscribeStatus":            {Level: AuthzLevelSessionHolder},
	servicePath + "SubscribeEvents":            {Level: AuthzLevelSessionHolder},
	servicePath + "GetEvents":                  {Level: AuthzLevelSessionHolder},
	servicePath + "ListNetworks":               {Level: AuthzLevelSessionHolder},
	servicePath + "SelectNetworks":             {Level: AuthzLevelSessionHolder, Audit: true},
	servicePath + "DeselectNetworks":           {Level: AuthzLevelSessionHolder, Audit: true},
	servicePath + "ForwardingRules":            {Level: AuthzLevelSessionHolder},
	servicePath + "ExposeService":              {Level: AuthzLevelSessionHolder, Audit: true},
	servicePath + "GetPeerSSHHostKey":          {Level: AuthzLevelSessionHolder},
	servicePath + "RequestJWTAuth":             {Level: AuthzLevelSessionHolder, Audit: true},
	servicePath + "WaitJWTToken":               {Level: AuthzLevelSessionHolder, Audit: true},
	servicePath + "RequestExtendAuthSession":   {Level: AuthzLevelSessionHolder},
	servicePath + "WaitExtendAuthSession":      {Level: AuthzLevelSessionHolder},
	servicePath + "WaitSSOLogin":               {Level: AuthzLevelSessionHolder, Audit: true},
	servicePath + "DismissSessionWarning":      {Level: AuthzLevelSessionHolder},
	servicePath + "DebugBundle":                {Level: AuthzLevelSessionHolder, Audit: true},
	servicePath + "SetLogLevel":                {Level: AuthzLevelSessionHolder},
	servicePath + "SetSyncResponsePersistence": {Level: AuthzLevelSessionHolder},
	servicePath + "StartCapture":               {Level: AuthzLevelSessionHolder, Audit: true},
	servicePath + "StartBundleCapture":         {Level: AuthzLevelSessionHolder, Audit: true},
	servicePath + "StopBundleCapture":          {Level: AuthzLevelSessionHolder},
	servicePath + "StartCPUProfile":            {Level: AuthzLevelSessionHolder},
	servicePath + "StopCPUProfile":             {Level: AuthzLevelSessionHolder},
	servicePath + "CleanState":                 {Level: AuthzLevelSessionHolder, Audit: true},
	servicePath + "DeleteState":                {Level: AuthzLevelSessionHolder, Audit: true},
	servicePath + "TracePacket":                {Level: AuthzLevelSessionHolder},
	servicePath + "RegisterUILog":              {Level: AuthzLevelSessionHolder},
	servicePath + "TriggerUpdate":              {Level: AuthzLevelSessionHolder, Audit: true},

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
