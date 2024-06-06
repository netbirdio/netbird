package refcounter

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
)

// ErrIgnore can be returned by AddFunc to indicate that the counter not be incremented for the given prefix.
var ErrIgnore = errors.New("ignore")

type Ref[O any] struct {
	Count int
	Out   O
}

type AddFunc[I, O any] func(prefix netip.Prefix, in I) (out O, err error)
type RemoveFunc[I, O any] func(prefix netip.Prefix, out O) error

type Counter[I, O any] struct {
	// refCountMap keeps track of the reference Ref for prefixes
	refCountMap map[netip.Prefix]Ref[O]
	refCountMu  sync.Mutex
	// idMap keeps track of the prefixes associated with an ID for removal
	idMap  map[string][]netip.Prefix
	idMu   sync.Mutex
	add    AddFunc[I, O]
	remove RemoveFunc[I, O]
}

// New creates a new Counter instance
func New[I, O any](add AddFunc[I, O], remove RemoveFunc[I, O]) *Counter[I, O] {
	return &Counter[I, O]{
		refCountMap: map[netip.Prefix]Ref[O]{},
		idMap:       map[string][]netip.Prefix{},
		add:         add,
		remove:      remove,
	}
}

// Increment increments the reference count for the given prefix.
// If this is the first reference to the prefix, the AddFunc is called.
func (rm *Counter[I, O]) Increment(prefix netip.Prefix, in I) (Ref[O], error) {
	rm.refCountMu.Lock()
	defer rm.refCountMu.Unlock()

	ref := rm.refCountMap[prefix]
	log.Tracef("Increasing ref count %d for prefix %s with [%v]", ref.Count, prefix, ref.Out)

	// Call AddFunc only if it's a new prefix
	if ref.Count == 0 {
		log.Tracef("Adding for prefix %s with [%v]", prefix, ref.Out)
		out, err := rm.add(prefix, in)

		if errors.Is(err, ErrIgnore) {
			return ref, nil
		}
		if err != nil {
			return ref, fmt.Errorf("failed to add for prefix %s: %w", prefix, err)
		}
		ref.Out = out
	}

	ref.Count++
	rm.refCountMap[prefix] = ref

	return ref, nil
}

// IncrementWithID increments the reference count for the given prefix and groups it under the given ID.
// If this is the first reference to the prefix, the AddFunc is called.
func (rm *Counter[I, O]) IncrementWithID(id string, prefix netip.Prefix, in I) (Ref[O], error) {
	rm.idMu.Lock()
	defer rm.idMu.Unlock()

	ref, err := rm.Increment(prefix, in)
	if err != nil {
		return ref, fmt.Errorf("with ID: %w", err)
	}
	rm.idMap[id] = append(rm.idMap[id], prefix)

	return ref, nil
}

// Decrement decrements the reference count for the given prefix.
// If the reference count reaches 0, the RemoveFunc is called.
func (rm *Counter[I, O]) Decrement(prefix netip.Prefix) (Ref[O], error) {
	rm.refCountMu.Lock()
	defer rm.refCountMu.Unlock()

	ref, ok := rm.refCountMap[prefix]
	if !ok {
		log.Tracef("No reference found for prefix %s", prefix)
		return ref, nil
	}

	log.Tracef("Decreasing ref count %d for prefix %s with [%v]", ref.Count, prefix, ref.Out)
	if ref.Count == 1 {
		log.Tracef("Removing for prefix %s with [%v]", prefix, ref.Out)
		if err := rm.remove(prefix, ref.Out); err != nil {
			return ref, fmt.Errorf("remove for prefix %s: %w", prefix, err)
		}
		delete(rm.refCountMap, prefix)
	} else {
		ref.Count--
		rm.refCountMap[prefix] = ref
	}

	return ref, nil
}

// DecrementWithID decrements the reference count for all prefixes associated with the given ID.
// If the reference count reaches 0, the RemoveFunc is called.
func (rm *Counter[I, O]) DecrementWithID(id string) error {
	rm.idMu.Lock()
	defer rm.idMu.Unlock()

	var merr *multierror.Error
	for _, prefix := range rm.idMap[id] {
		if _, err := rm.Decrement(prefix); err != nil {
			merr = multierror.Append(merr, err)
		}
	}
	delete(rm.idMap, id)

	return nberrors.FormatErrorOrNil(merr)
}

// Flush removes all references and calls RemoveFunc for each prefix.
func (rm *Counter[I, O]) Flush() error {
	rm.refCountMu.Lock()
	defer rm.refCountMu.Unlock()
	rm.idMu.Lock()
	defer rm.idMu.Unlock()

	var merr *multierror.Error
	for prefix := range rm.refCountMap {
		log.Tracef("Removing for prefix %s", prefix)
		ref := rm.refCountMap[prefix]
		if err := rm.remove(prefix, ref.Out); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove for prefix %s: %w", prefix, err))
		}
	}
	rm.refCountMap = map[netip.Prefix]Ref[O]{}

	rm.idMap = map[string][]netip.Prefix{}

	return nberrors.FormatErrorOrNil(merr)
}
