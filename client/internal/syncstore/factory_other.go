//go:build !ios

package syncstore

// New returns the platform default store. On all non-iOS platforms the sync
// response is kept in memory; dir is unused.
func New(_ string) Store {
	return NewMemoryStore()
}
