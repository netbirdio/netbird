//go:build windows

package debug

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	log "github.com/sirupsen/logrus"
)

const (
	// The NRPT policy table is reachable through the CIM class that backs
	// Get-DnsClientNrptPolicy. Unlike the rules in the registry, the table is
	// what the resolver currently has loaded, which is the only way to tell an
	// applied rule from one that is merely written, in either direction.
	nrptPolicyNamespace = `root\Microsoft\Windows\DNS`
	nrptPolicyClass     = "PS_DnsClientNrptPolicy"
	nrptPolicyMethod    = "Get"

	// The class has no instances, so the table comes from the out parameters
	// of a static method call, rendered as MOF text: the embedded instances
	// arrive as a safe array of objects, which cannot be read back through the
	// COM bindings, and the text form carries all of them.
	nrptPolicyInstanceKeyword = "instance of DnsClientPolicyConfiguration"

	nrptPolicyTimeout = 15 * time.Second
)

// COM initialization results that leave the calling thread usable: S_FALSE for
// a thread this process already initialized, RPC_E_CHANGED_MODE for one that
// belongs to another apartment.
const (
	sFalse          = 0x00000001
	rpcEChangedMode = 0x80010106
)

// nrptQueryInFlight admits one read of the policy table at a time. A provider
// that stops answering keeps its goroutine and the OS thread that goroutine
// pinned, so a later bundle reports that instead of pinning another one.
var nrptQueryInFlight = make(chan struct{}, 1)

// nrptPolicyEntry is one namespace of the effective policy table, holding the
// values of an embedded DnsClientPolicyConfiguration instance in the order the
// provider reported them.
type nrptPolicyEntry struct {
	namespace string
	values    []registryValue
}

// registryValue is a name and its rendered value, shared by the registry and
// policy table readers so both anonymize by value name the same way.
type registryValue struct {
	name  string
	value string
}

// effectiveNRPTPolicies reads the effective NRPT table. The call is bounded
// because a WMI provider can block indefinitely and a debug bundle must not.
func effectiveNRPTPolicies() ([]nrptPolicyEntry, error) {
	type result struct {
		text string
		err  error
	}

	select {
	case nrptQueryInFlight <- struct{}{}:
	default:
		return nil, errors.New("an earlier read of the policy table has not returned")
	}

	done := make(chan result, 1)
	go func() {
		// the slot is released here rather than by the caller, so a read that
		// outlives the timeout holds it until the provider answers
		defer func() { <-nrptQueryInFlight }()

		text, err := nrptPolicyTableText()
		done <- result{text: text, err: err}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			return nil, res.err
		}
		return parseNRPTPolicyTable(res.text), nil
	case <-time.After(nrptPolicyTimeout):
		return nil, errors.New("read of the policy table timed out")
	}
}

// nrptPolicyTableText calls the policy table method and returns the MOF text of
// its out parameters.
func nrptPolicyTableText() (text string, err error) {
	// COM is per thread, and the collection is short lived, so the thread is
	// pinned for the duration rather than initialized for the process.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	defer func() {
		// The COM call chain is dynamically typed, so a provider that answers
		// with an unexpected shape must not take the daemon down with it.
		if r := recover(); r != nil {
			err = fmt.Errorf("read NRPT policy table: %v", r)
		}
	}()

	owns, err := coInitialize()
	if err != nil {
		return "", err
	}
	if owns {
		defer ole.CoUninitialize()
	}

	locator, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return "", fmt.Errorf("create WMI locator: %w", err)
	}
	defer locator.Release()

	dispatch, err := locator.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return "", fmt.Errorf("query WMI locator interface: %w", err)
	}
	defer dispatch.Release()

	service, err := dispatchCall(dispatch, "ConnectServer", nil, nrptPolicyNamespace)
	if err != nil {
		return "", fmt.Errorf("connect to %s: %w", nrptPolicyNamespace, err)
	}
	defer service.Release()

	inParams, err := spawnMethodInParams(service)
	if err != nil {
		return "", err
	}
	defer inParams.Release()

	// The effective table is the merge of the local and the group policy
	// store, which is what the resolver answers from.
	if _, err := oleutil.PutProperty(inParams, "Effective", true); err != nil {
		return "", fmt.Errorf("set Effective parameter: %w", err)
	}

	outParams, err := dispatchCall(service, "ExecMethod", nrptPolicyClass, nrptPolicyMethod, inParams)
	if err != nil {
		return "", fmt.Errorf("call %s.%s: %w", nrptPolicyClass, nrptPolicyMethod, err)
	}
	defer outParams.Release()

	textVariant, err := oleutil.CallMethod(outParams, "GetObjectText_")
	if err != nil {
		return "", fmt.Errorf("render policy table: %w", err)
	}
	defer func() {
		if err := textVariant.Clear(); err != nil {
			log.Debugf("clear policy table variant: %v", err)
		}
	}()

	return textVariant.ToString(), nil
}

// spawnMethodInParams builds the in parameters instance the method needs. The
// provider rejects the call without one, even when every parameter is optional.
func spawnMethodInParams(service *ole.IDispatch) (*ole.IDispatch, error) {
	class, err := dispatchCall(service, "Get", nrptPolicyClass)
	if err != nil {
		return nil, fmt.Errorf("get class %s: %w", nrptPolicyClass, err)
	}
	defer class.Release()

	methods, err := dispatchProperty(class, "Methods_")
	if err != nil {
		return nil, fmt.Errorf("get class methods: %w", err)
	}
	defer methods.Release()

	method, err := dispatchCall(methods, "Item", nrptPolicyMethod)
	if err != nil {
		return nil, fmt.Errorf("get method %s: %w", nrptPolicyMethod, err)
	}
	defer method.Release()

	params, err := dispatchProperty(method, "InParameters")
	if err != nil {
		return nil, fmt.Errorf("get method parameters: %w", err)
	}
	defer params.Release()

	inParams, err := dispatchCall(params, "SpawnInstance_")
	if err != nil {
		return nil, fmt.Errorf("spawn parameter instance: %w", err)
	}

	return inParams, nil
}

// parseNRPTPolicyTable pulls the embedded instances out of the MOF text. Each
// instance is a namespace of the table, with one name and value per line.
func parseNRPTPolicyTable(text string) []nrptPolicyEntry {
	var entries []nrptPolicyEntry
	var current *nrptPolicyEntry

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ";"))

		switch {
		case strings.HasPrefix(line, nrptPolicyInstanceKeyword):
			entries = append(entries, nrptPolicyEntry{})
			current = &entries[len(entries)-1]
			continue
		case strings.HasPrefix(line, "}"):
			// closes an instance, and the array with the last one, so the
			// class level parameters that follow are not read as values
			current = nil
			continue
		case current == nil, line == "{":
			continue
		}

		name, value, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}

		value = unquoteMOFValue(value)
		if name == "Namespace" {
			current.namespace = value
			continue
		}

		current.values = append(current.values, registryValue{name: name, value: value})
	}

	return entries
}

// unquoteMOFValue renders a MOF scalar or array as plain text: "a" becomes a,
// and {"a", "b"} becomes a, b.
func unquoteMOFValue(value string) string {
	value = strings.TrimSpace(value)

	if inner, ok := strings.CutPrefix(value, "{"); ok {
		value = strings.TrimSuffix(inner, "}")

		entries := strings.Split(value, ",")
		for i, entry := range entries {
			entries[i] = strings.Trim(strings.TrimSpace(entry), `"`)
		}
		return strings.Join(entries, ", ")
	}

	return strings.Trim(value, `"`)
}

// coInitialize prepares the calling thread for COM and reports whether this
// call owns the initialization, which decides whether it may be balanced with
// CoUninitialize. S_FALSE took a reference on a thread this process had already
// initialized and so has to be released, while RPC_E_CHANGED_MODE took none:
// the thread belongs to another apartment, which is usable but is not ours to
// uninitialize.
func coInitialize() (bool, error) {
	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err == nil {
		return true, nil
	}

	var oleErr *ole.OleError
	if errors.As(err, &oleErr) {
		switch oleErr.Code() {
		case sFalse:
			return true, nil
		case rpcEChangedMode:
			return false, nil
		}
	}

	return false, fmt.Errorf("initialize COM: %w", err)
}

// dispatchCall calls a COM method that returns an object.
func dispatchCall(dispatch *ole.IDispatch, method string, params ...any) (*ole.IDispatch, error) {
	variant, err := oleutil.CallMethod(dispatch, method, params...)
	if err != nil {
		return nil, err
	}

	object := variant.ToIDispatch()
	if object == nil {
		return nil, fmt.Errorf("%s returned no object", method)
	}

	return object, nil
}

// dispatchProperty reads a COM property that holds an object.
func dispatchProperty(dispatch *ole.IDispatch, property string) (*ole.IDispatch, error) {
	variant, err := oleutil.GetProperty(dispatch, property)
	if err != nil {
		return nil, err
	}

	object := variant.ToIDispatch()
	if object == nil {
		return nil, fmt.Errorf("property %s holds no object", property)
	}

	return object, nil
}
