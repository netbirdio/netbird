//go:build ios

package syncstore

// New returns the platform default store. On iOS the sync response is
// serialized to disk (in dir) to keep it out of the constrained process memory.
func New(dir string) Store {
	return NewDiskStore(dir)
}
