package elevate

// adminWriteGIDs are the groups whose write access to an executable does not
// widen who could authorize elevating it.
//
// macOS installs applications as root:admin, mode 0775, /Applications included,
// so requiring owner-only write would reject every normal install. Group admin
// (gid 80) is exactly the set of accounts that can answer the authentication
// dialog, so its write access grants nothing the prompt would not.
var adminWriteGIDs = []uint32{0, 80}
