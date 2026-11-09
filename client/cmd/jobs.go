package cmd

// remoteJobsAllowedFlag opts this peer into running remote jobs (e.g. debug
// bundles) requested by the management server. It defaults to false: remote
// jobs are an explicit opt-in, and enabling it is a privileged change (see the
// daemon gate in client/server), mirroring the SSH server opt-in.
const remoteJobsAllowedFlag = "allow-remote-jobs"

var remoteJobsAllowed bool

func init() {
	upCmd.PersistentFlags().BoolVar(&remoteJobsAllowed, remoteJobsAllowedFlag, false, "Allow the management server to run remote jobs (e.g. debug bundles) on this peer")
}
