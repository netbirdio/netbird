package owner

// UID is a Unix user ID. Defined as a distinct type so it can't be silently
// swapped with GID, PID, or other uint32 values at call sites.
type UID uint32
