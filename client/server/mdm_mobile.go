//go:build ios || android

package server

// OnMDMPolicyChanged is the mobile entry point invoked by the native
// layer (Kotlin / Swift) when the OS broadcasts an MDM configuration
// change (ACTION_APPLICATION_RESTRICTIONS_CHANGED on Android,
// UserDefaults.didChangeNotification on iOS). The OS notification only
// signals "something changed" — no payload — so this hook re-runs the
// same load-and-diff sequence the desktop ticker triggers on each
// tick. The fresh policy values are read on demand by
// mdm.loadPlatformPolicy, which on mobile delegates to the
// PolicyFetcher registered by the native layer via
// mdm.SetMobilePolicyFetcher.
//
// Safe to call at any time after Server construction. Re-entrancy is
// serialised by the s.mutex acquired inside onMDMPolicyChange.
func (s *Server) OnMDMPolicyChanged() {
	s.onMDMPolicyChange(nil, nil)
}
