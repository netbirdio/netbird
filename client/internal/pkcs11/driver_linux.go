//go:build pkcs11 && linux && (amd64 || arm64)

package pkcs11

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"github.com/ebitengine/purego"
)

// ulong is CK_ULONG, an unsigned long, which is pointer-sized on the 64-bit Linux ABIs
// this file builds for. The struct layouts below assume that width and natural alignment.
type ulong = uintptr

const (
	unavailableInformation = ^ulong(0)

	flagOSLockingOK   = 0x2
	flagRWSession     = 0x2
	flagSerialSession = 0x4
	userTypeUser      = 0x1

	findBatch = 32
)

type version struct {
	major byte
	minor byte
}

type attribute struct {
	typ   ulong
	value unsafe.Pointer
	len   ulong
}

type mechanism struct {
	typ       ulong
	parameter unsafe.Pointer
	len       ulong
}

type pssParams struct {
	hashAlg ulong
	mgf     ulong
	saltLen ulong
}

type tokenInfo struct {
	label          [32]byte
	manufacturerID [32]byte
	model          [16]byte
	serialNumber   [16]byte
	flags          ulong
	counters       [10]ulong
	hardware       version
	firmware       version
	utcTime        [16]byte
}

type initializeArgs struct {
	createMutex  uintptr
	destroyMutex uintptr
	lockMutex    uintptr
	unlockMutex  uintptr
	flags        ulong
	reserved     unsafe.Pointer
}

// functionList mirrors CK_FUNCTION_LIST: a CK_VERSION padded to pointer alignment, then
// the PKCS#11 v2.40 entry points in specification order.
type functionList struct {
	version version
	_       [6]byte
	fn      [68]uintptr
}

const (
	fnInitialize        = 0
	fnGetSlotList       = 4
	fnGetTokenInfo      = 6
	fnOpenSession       = 12
	fnCloseSession      = 13
	fnLogin             = 18
	fnLogout            = 19
	fnCreateObject      = 20
	fnGetAttributeValue = 24
	fnFindObjectsInit   = 26
	fnFindObjects       = 27
	fnFindObjectsFinal  = 28
	fnSignInit          = 42
	fnSign              = 43
)

// module holds the entry points of one loaded library, bound straight from its
// CK_FUNCTION_LIST.
type module struct {
	cInitialize        func(args *initializeArgs) ulong
	cGetSlotList       func(tokenPresent byte, slots *ulong, count *ulong) ulong
	cGetTokenInfo      func(slot ulong, info *tokenInfo) ulong
	cOpenSession       func(slot ulong, flags ulong, application unsafe.Pointer, notify uintptr, session *ulong) ulong
	cCloseSession      func(session ulong) ulong
	cLogin             func(session ulong, userType ulong, pin *byte, pinLen ulong) ulong
	cLogout            func(session ulong) ulong
	cCreateObject      func(session ulong, template *attribute, count ulong, object *ulong) ulong
	cGetAttributeValue func(session ulong, object ulong, template *attribute, count ulong) ulong
	cFindObjectsInit   func(session ulong, template *attribute, count ulong) ulong
	cFindObjects       func(session ulong, objects *ulong, max ulong, count *ulong) ulong
	cFindObjectsFinal  func(session ulong) ulong
	cSignInit          func(session ulong, mech *mechanism, key ulong) ulong
	cSign              func(session ulong, data *byte, dataLen ulong, signature *byte, signatureLen *ulong) ulong
}

func load(path string) (driver, error) {
	lib, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, fmt.Errorf("open PKCS#11 module %s: %w", path, err)
	}
	symbol, err := purego.Dlsym(lib, "C_GetFunctionList")
	if err != nil {
		return nil, fmt.Errorf("%s is not a PKCS#11 module: %w", path, err)
	}
	var getFunctionList func(list **functionList) ulong
	purego.RegisterFunc(&getFunctionList, symbol)
	var list *functionList
	if rv := getFunctionList(&list); rv != rvOK || list == nil {
		return nil, Error{Op: "C_GetFunctionList", Code: uint(rv)}
	}

	m := &module{}
	for _, entry := range []struct {
		fn    any
		index int
	}{
		{&m.cInitialize, fnInitialize},
		{&m.cGetSlotList, fnGetSlotList},
		{&m.cGetTokenInfo, fnGetTokenInfo},
		{&m.cOpenSession, fnOpenSession},
		{&m.cCloseSession, fnCloseSession},
		{&m.cLogin, fnLogin},
		{&m.cLogout, fnLogout},
		{&m.cCreateObject, fnCreateObject},
		{&m.cGetAttributeValue, fnGetAttributeValue},
		{&m.cFindObjectsInit, fnFindObjectsInit},
		{&m.cFindObjects, fnFindObjects},
		{&m.cFindObjectsFinal, fnFindObjectsFinal},
		{&m.cSignInit, fnSignInit},
		{&m.cSign, fnSign},
	} {
		if list.fn[entry.index] == 0 {
			return nil, fmt.Errorf("%s lacks PKCS#11 entry point %d", path, entry.index)
		}
		purego.RegisterFunc(entry.fn, list.fn[entry.index])
	}

	args := &initializeArgs{flags: flagOSLockingOK}
	if rv := m.cInitialize(args); rv != rvOK && rv != rvAlreadyInitialized {
		return nil, Error{Op: "C_Initialize", Code: uint(rv)}
	}
	return m, nil
}

func (m *module) tokens() ([]Token, error) {
	var count ulong
	if rv := m.cGetSlotList(1, nil, &count); rv != rvOK {
		return nil, Error{Op: "C_GetSlotList", Code: uint(rv)}
	}
	if count == 0 {
		return nil, nil
	}
	slots := make([]ulong, count)
	if rv := m.cGetSlotList(1, &slots[0], &count); rv != rvOK {
		return nil, Error{Op: "C_GetSlotList", Code: uint(rv)}
	}

	tokens := make([]Token, 0, count)
	for _, slot := range slots[:count] {
		var info tokenInfo
		if rv := m.cGetTokenInfo(slot, &info); rv != rvOK {
			continue
		}
		tokens = append(tokens, Token{Slot: uint(slot), Label: strings.TrimRight(string(info.label[:]), " \x00")})
	}
	return tokens, nil
}

func (m *module) openSession(slot uint, readWrite bool) (uint, error) {
	flags := ulong(flagSerialSession)
	if readWrite {
		flags |= flagRWSession
	}
	var session ulong
	if rv := m.cOpenSession(ulong(slot), flags, nil, 0, &session); rv != rvOK {
		return 0, Error{Op: "C_OpenSession", Code: uint(rv)}
	}
	return uint(session), nil
}

func (m *module) closeSession(session uint) {
	m.cCloseSession(ulong(session))
}

func (m *module) login(session uint, pin []byte) error {
	var pinPtr *byte
	if len(pin) > 0 {
		pinPtr = &pin[0]
	}
	rv := m.cLogin(ulong(session), userTypeUser, pinPtr, ulong(len(pin)))
	runtime.KeepAlive(pin)
	if rv != rvOK && rv != rvUserAlreadyLoggedIn {
		return Error{Op: "C_Login", Code: uint(rv)}
	}
	return nil
}

func (m *module) logout(session uint) {
	m.cLogout(ulong(session))
}

func (m *module) findObjects(session uint, template []Attribute) ([]Object, error) {
	attrs := toAttributes(template)
	rv := m.cFindObjectsInit(ulong(session), first(attrs), ulong(len(attrs)))
	runtime.KeepAlive(template)
	if rv != rvOK {
		return nil, Error{Op: "C_FindObjectsInit", Code: uint(rv)}
	}
	defer m.cFindObjectsFinal(ulong(session))

	var objects []Object
	for {
		var batch [findBatch]ulong
		var count ulong
		if rv := m.cFindObjects(ulong(session), &batch[0], findBatch, &count); rv != rvOK {
			return nil, Error{Op: "C_FindObjects", Code: uint(rv)}
		}
		for _, handle := range batch[:count] {
			objects = append(objects, Object(handle))
		}
		if count < findBatch {
			return objects, nil
		}
	}
}

func (m *module) attribute(session uint, obj Object, typ uint) ([]byte, error) {
	attr := attribute{typ: ulong(typ)}
	if rv := m.cGetAttributeValue(ulong(session), ulong(obj), &attr, 1); rv != rvOK {
		return nil, Error{Op: "C_GetAttributeValue", Code: uint(rv)}
	}
	if attr.len == unavailableInformation {
		return nil, fmt.Errorf("attribute 0x%x is unavailable", typ)
	}
	if attr.len == 0 {
		return nil, nil
	}
	value := make([]byte, attr.len)
	attr.value = unsafe.Pointer(&value[0])
	rv := m.cGetAttributeValue(ulong(session), ulong(obj), &attr, 1)
	runtime.KeepAlive(value)
	if rv != rvOK {
		return nil, Error{Op: "C_GetAttributeValue", Code: uint(rv)}
	}
	return value[:attr.len], nil
}

func (m *module) sign(session uint, mech Mechanism, key Object, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("nothing to sign")
	}
	native := mechanism{typ: ulong(mech.Type)}
	var params *pssParams
	if mech.PSS != nil {
		params = &pssParams{hashAlg: ulong(mech.PSS.Hash), mgf: ulong(mech.PSS.MGF), saltLen: ulong(mech.PSS.SaltLen)}
		native.parameter = unsafe.Pointer(params)
		native.len = ulong(unsafe.Sizeof(*params))
	}
	rv := m.cSignInit(ulong(session), &native, ulong(key))
	runtime.KeepAlive(params)
	if rv != rvOK {
		return nil, Error{Op: "C_SignInit", Code: uint(rv)}
	}

	var size ulong
	if rv := m.cSign(ulong(session), &data[0], ulong(len(data)), nil, &size); rv != rvOK {
		return nil, Error{Op: "C_Sign", Code: uint(rv)}
	}
	signature := make([]byte, size)
	rv = m.cSign(ulong(session), &data[0], ulong(len(data)), &signature[0], &size)
	runtime.KeepAlive(data)
	if rv != rvOK {
		return nil, Error{Op: "C_Sign", Code: uint(rv)}
	}
	return signature[:size], nil
}

func (m *module) createObject(session uint, template []Attribute) (Object, error) {
	attrs := toAttributes(template)
	var object ulong
	rv := m.cCreateObject(ulong(session), first(attrs), ulong(len(attrs)), &object)
	runtime.KeepAlive(template)
	if rv != rvOK {
		return 0, Error{Op: "C_CreateObject", Code: uint(rv)}
	}
	return Object(object), nil
}

func toAttributes(template []Attribute) []attribute {
	attrs := make([]attribute, len(template))
	for i, a := range template {
		attrs[i].typ = ulong(a.Type)
		if len(a.Value) > 0 {
			attrs[i].value = unsafe.Pointer(&a.Value[0])
			attrs[i].len = ulong(len(a.Value))
		}
	}
	return attrs
}

func first(attrs []attribute) *attribute {
	if len(attrs) == 0 {
		return nil
	}
	return &attrs[0]
}
