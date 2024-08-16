package refcounter

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
)

const logLevel = log.TraceLevel

// ErrIgnore can be returned by AddFunc to indicate that the counter should not be incremented for the given key.
var ErrIgnore = errors.New("ignore")

// Ref holds the reference count and associated data for a key.
type Ref[O any] struct {
	Count int
	Out   O
}

// AddFunc is the function type for adding a new key.
// Key is the type of the key (e.g., netip.Prefix).
type AddFunc[Key, I, O any] func(key Key, in I) (out O, err error)

// RemoveFunc is the function type for removing a key.
type RemoveFunc[Key, O any] func(key Key, out O) error

// Counter is a generic reference counter for managing keys and their associated data.
// Key: The type of the key (e.g., netip.Prefix, string).
//
// I: The input type for the AddFunc. It is the input type for additional data needed
// when adding a key, it is passed as the second argument to AddFunc.
//
// O: The output type for the AddFunc and RemoveFunc. This is the output returned by AddFunc.
// It is stored and passed to RemoveFunc when the reference count reaches 0.
//
// The types can be aliased to a specific type using the following syntax:
//
//	type RouteRefCounter = Counter[netip.Prefix, any, any]
type Counter[Key comparable, I, O any] struct {
	// refCountMap keeps track of the reference Ref for keys
	refCountMap map[Key]Ref[O]
	refCountMu  sync.Mutex
	// idMap keeps track of the keys associated with an ID for removal
	idMap  map[string][]Key
	idMu   sync.Mutex
	add    AddFunc[Key, I, O]
	remove RemoveFunc[Key, O]
}

// New creates a new Counter instance.
// Usage example:
//
//	counter := New[netip.Prefix, string, string](
//	    func(key netip.Prefix, in string) (out string, err error) { ... },
//	    func(key netip.Prefix, out string) error { ... },`
//	)
func New[Key comparable, I, O any](add AddFunc[Key, I, O], remove RemoveFunc[Key, O]) *Counter[Key, I, O] {
	return &Counter[Key, I, O]{
		refCountMap: map[Key]Ref[O]{},
		idMap:       map[string][]Key{},
		add:         add,
		remove:      remove,
	}
}

// Get retrieves the current reference count and associated data for a key.
// If the key doesn't exist, it returns a zero value Ref and false.
func (rm *Counter[Key, I, O]) Get(key Key) (Ref[O], bool) {
	rm.refCountMu.Lock()
	defer rm.refCountMu.Unlock()

	ref, ok := rm.refCountMap[key]
	return ref, ok
}

// Increment increments the reference count for the given key.
// If this is the first reference to the key, the AddFunc is called.
func (rm *Counter[Key, I, O]) Increment(key Key, in I) (Ref[O], error) {
	rm.refCountMu.Lock()
	defer rm.refCountMu.Unlock()

	ref := rm.refCountMap[key]
	logCallerF("Increasing ref count [%d -> %d] for key %v with In [%v] Out [%v]", ref.Count, ref.Count+1, key, in, ref.Out)

	// Call AddFunc only if it's a new key
	if ref.Count == 0 {
		logCallerF("Calling add for key %v", key)
		out, err := rm.add(key, in)

		if errors.Is(err, ErrIgnore) {
			return ref, nil
		}
		if err != nil {
			return ref, fmt.Errorf("failed to add for key %v: %w", key, err)
		}
		ref.Out = out
	}

	ref.Count++
	rm.refCountMap[key] = ref

	return ref, nil
}

// IncrementWithID increments the reference count for the given key and groups it under the given ID.
// If this is the first reference to the key, the AddFunc is called.
func (rm *Counter[Key, I, O]) IncrementWithID(id string, key Key, in I) (Ref[O], error) {
	rm.idMu.Lock()
	defer rm.idMu.Unlock()

	ref, err := rm.Increment(key, in)
	if err != nil {
		return ref, fmt.Errorf("with ID: %w", err)
	}
	rm.idMap[id] = append(rm.idMap[id], key)

	return ref, nil
}

// Decrement decrements the reference count for the given key.
// If the reference count reaches 0, the RemoveFunc is called.
func (rm *Counter[Key, I, O]) Decrement(key Key) (Ref[O], error) {
	rm.refCountMu.Lock()
	defer rm.refCountMu.Unlock()

	ref, ok := rm.refCountMap[key]
	if !ok {
		logCallerF("No reference found for key %v", key)
		return ref, nil
	}

	logCallerF("Decreasing ref count [%d -> %d] for key %v with Out [%v]", ref.Count, ref.Count-1, key, ref.Out)
	if ref.Count == 1 {
		logCallerF("Calling remove for key %v", key)
		if err := rm.remove(key, ref.Out); err != nil {
			return ref, fmt.Errorf("remove for key %v: %w", key, err)
		}
		delete(rm.refCountMap, key)
	} else {
		ref.Count--
		rm.refCountMap[key] = ref
	}

	return ref, nil
}

// DecrementWithID decrements the reference count for all keys associated with the given ID.
// If the reference count reaches 0, the RemoveFunc is called.
func (rm *Counter[Key, I, O]) DecrementWithID(id string) error {
	rm.idMu.Lock()
	defer rm.idMu.Unlock()

	var merr *multierror.Error
	for _, key := range rm.idMap[id] {
		if _, err := rm.Decrement(key); err != nil {
			merr = multierror.Append(merr, err)
		}
	}
	delete(rm.idMap, id)

	return nberrors.FormatErrorOrNil(merr)
}

// Flush removes all references and calls RemoveFunc for each key.
func (rm *Counter[Key, I, O]) Flush() error {
	rm.refCountMu.Lock()
	defer rm.refCountMu.Unlock()
	rm.idMu.Lock()
	defer rm.idMu.Unlock()

	var merr *multierror.Error
	for key := range rm.refCountMap {
		logCallerF("Calling remove for key %v", key)
		ref := rm.refCountMap[key]
		if err := rm.remove(key, ref.Out); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove for key %v: %w", key, err))
		}
	}

	clear(rm.refCountMap)
	clear(rm.idMap)

	return nberrors.FormatErrorOrNil(merr)
}

// Clear removes all references without calling RemoveFunc.
func (rm *Counter[Key, I, O]) Clear() {
	rm.refCountMu.Lock()
	defer rm.refCountMu.Unlock()
	rm.idMu.Lock()
	defer rm.idMu.Unlock()

	clear(rm.refCountMap)
	clear(rm.idMap)
}

func getCallerInfo(depth int, maxDepth int) (string, bool) {
	if depth >= maxDepth {
		return "", false
	}

	pc, _, _, ok := runtime.Caller(depth)
	if !ok {
		return "", false
	}

	if details := runtime.FuncForPC(pc); details != nil {
		name := details.Name()

		lastDotIndex := strings.LastIndex(name, "/")
		if lastDotIndex != -1 {
			name = name[lastDotIndex+1:]
		}

		if strings.HasPrefix(name, "refcounter.") {
			// +2 to account for recursion
			return getCallerInfo(depth+2, maxDepth)
		}

		return name, true
	}

	return "", false
}

// logCaller logs a message with the package name and method of the function that called the current function.
func logCallerF(format string, args ...interface{}) {
	if log.GetLevel() < logLevel {
		return
	}

	if callerName, ok := getCallerInfo(3, 18); ok {
		format = fmt.Sprintf("[%s] %s", callerName, format)
	}

	log.StandardLogger().Logf(logLevel, format, args...)
}
