package manager

import "sync"

// fqdnMutexMap serializes auto-configure operations per FQDN within a
// single management process.
//
// Without this, two concurrent CreateDomain calls for the same FQDN
// could both pass the "is there an existing CNAME?" check, both write,
// and depending on the provider end up with duplicate or conflicting
// records. Cloudflare and Route 53 dedupe server-side; DigitalOcean and
// RFC 2136 do not. A coarse per-FQDN mutex is cheap and sufficient —
// domain creation is not load-bearing throughput.
//
// This is single-process serialization. Multi-replica management would
// need a distributed lock; out of scope for v1 since management is
// typically single-replica today.
type fqdnMutexMap struct {
	m sync.Map // map[string]*sync.Mutex
}

func newFQDNMutexMap() *fqdnMutexMap {
	return &fqdnMutexMap{}
}

// Lock acquires the mutex for fqdn and returns a function that releases it.
//
//	unlock := mut.Lock(fqdn)
//	defer unlock()
func (f *fqdnMutexMap) Lock(fqdn string) func() {
	v, _ := f.m.LoadOrStore(fqdn, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}
