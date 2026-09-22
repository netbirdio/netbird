// Package pkcs11 is a minimal PKCS#11 client. It loads a module at runtime without cgo,
// opens a token session, lists objects and signs with keys the token holds. It exists so
// certificates whose keys live in a TPM behind tpm2-pkcs11 can be proven; whatever a
// certificate store does not need is left out.
package pkcs11

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// Object classes, attribute types, mechanisms and generators from PKCS#11 v2.40.
const (
	ClassCertificate = 0x1
	ClassPublicKey   = 0x2
	ClassPrivateKey  = 0x3

	CertificateX509 = 0x0

	AttrClass           = 0x0
	AttrToken           = 0x1
	AttrLabel           = 0x3
	AttrValue           = 0x11
	AttrCertificateType = 0x80
	AttrKeyType         = 0x100
	AttrSubject         = 0x101
	AttrID              = 0x102
	AttrModulus         = 0x120
	AttrPublicExponent  = 0x122
	AttrECParams        = 0x180
	AttrECPoint         = 0x181

	KeyRSA = 0x0
	KeyEC  = 0x3

	MechRSAPKCSPSS = 0xd
	MechSHA256     = 0x250
	MechSHA384     = 0x260
	MechECDSA      = 0x1041

	MGF1SHA256 = 0x2
	MGF1SHA384 = 0x3

	rvOK                  = 0x0
	rvUserAlreadyLoggedIn = 0x100
	rvAlreadyInitialized  = 0x191
)

var ErrUnsupported = errors.New("PKCS#11 modules need a build with the pkcs11 tag on linux/amd64 or linux/arm64")

// Error is a PKCS#11 return value other than CKR_OK.
type Error struct {
	Op   string
	Code uint
}

func (e Error) Error() string {
	if name, ok := returnValueNames[e.Code]; ok {
		return fmt.Sprintf("%s: %s", e.Op, name)
	}
	return fmt.Sprintf("%s: CKR 0x%x", e.Op, e.Code)
}

var returnValueNames = map[uint]string{
	0x2:   "CKR_HOST_MEMORY",
	0x3:   "CKR_SLOT_ID_INVALID",
	0x5:   "CKR_GENERAL_ERROR",
	0x7:   "CKR_ARGUMENTS_BAD",
	0x12:  "CKR_ATTRIBUTE_TYPE_INVALID",
	0x13:  "CKR_ATTRIBUTE_VALUE_INVALID",
	0x30:  "CKR_DEVICE_ERROR",
	0x54:  "CKR_FUNCTION_NOT_SUPPORTED",
	0x68:  "CKR_KEY_FUNCTION_NOT_PERMITTED",
	0x70:  "CKR_MECHANISM_INVALID",
	0x71:  "CKR_MECHANISM_PARAM_INVALID",
	0x82:  "CKR_OBJECT_HANDLE_INVALID",
	0xa0:  "CKR_PIN_INCORRECT",
	0xa4:  "CKR_PIN_LOCKED",
	0xb3:  "CKR_SESSION_HANDLE_INVALID",
	0xd0:  "CKR_TEMPLATE_INCOMPLETE",
	0xd1:  "CKR_TEMPLATE_INCONSISTENT",
	0xe0:  "CKR_TOKEN_NOT_PRESENT",
	0x101: "CKR_USER_NOT_LOGGED_IN",
	0x150: "CKR_BUFFER_TOO_SMALL",
	0x190: "CKR_CRYPTOKI_NOT_INITIALIZED",
}

// Attribute is one entry of a PKCS#11 template. Integer-valued attributes such as the
// object class are encoded with ULong.
type Attribute struct {
	Type  uint
	Value []byte
}

// Mechanism selects a signing algorithm. PSS carries the parameters CKM_RSA_PKCS_PSS needs.
type Mechanism struct {
	Type uint
	PSS  *PSSParams
}

type PSSParams struct {
	Hash    uint
	MGF     uint
	SaltLen uint
}

// Object is a handle the token issued for one of its objects.
type Object uint

// Token is a slot with a token present.
type Token struct {
	Slot  uint
	Label string
}

// Module is a loaded and initialised PKCS#11 library. A module is loaded once per path
// and never finalised: tokens such as tpm2-pkcs11 do real work in C_Initialize, and the
// process exit releases everything anyway.
type Module struct {
	d driver
}

var (
	modulesMu sync.Mutex
	modules   = map[string]*Module{}
)

// Load opens the shared library at path and initialises it, or returns the module already
// loaded from that path.
func Load(path string) (*Module, error) {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	if m, ok := modules[path]; ok {
		return m, nil
	}
	d, err := load(path)
	if err != nil {
		return nil, err
	}
	m := &Module{d: d}
	modules[path] = m
	return m, nil
}

func (m *Module) Tokens() ([]Token, error) {
	return m.d.tokens()
}

// OpenSession opens a read-only session with the token carrying label, or with the first
// token when label is empty, and logs in as the user when pin is not nil. An empty,
// non-nil pin still logs in.
func (m *Module) OpenSession(label string, pin []byte) (*Session, error) {
	return m.openSession(label, pin, false)
}

// OpenReadWriteSession is OpenSession for callers that create objects on the token.
func (m *Module) OpenReadWriteSession(label string, pin []byte) (*Session, error) {
	return m.openSession(label, pin, true)
}

func (m *Module) openSession(label string, pin []byte, readWrite bool) (*Session, error) {
	token, err := m.token(label)
	if err != nil {
		return nil, err
	}
	handle, err := m.d.openSession(token.Slot, readWrite)
	if err != nil {
		return nil, err
	}
	s := &Session{d: m.d, handle: handle}
	if pin == nil {
		return s, nil
	}
	if err := m.d.login(handle, pin); err != nil {
		s.Close()
		return nil, err
	}
	s.loggedIn = true
	return s, nil
}

func (m *Module) token(label string) (Token, error) {
	tokens, err := m.Tokens()
	if err != nil {
		return Token{}, err
	}
	for _, token := range tokens {
		if label == "" || token.Label == label {
			return token, nil
		}
	}
	if label == "" {
		return Token{}, errors.New("no token present")
	}
	return Token{}, fmt.Errorf("no token labelled %q among %d tokens", label, len(tokens))
}

// Session is an open session with one token. Close logs out again if the session logged in.
type Session struct {
	d        driver
	handle   uint
	loggedIn bool
}

func (s *Session) Close() {
	if s.loggedIn {
		s.d.logout(s.handle)
	}
	s.d.closeSession(s.handle)
}

// FindObjects returns the handles of every object matching all attributes of template.
func (s *Session) FindObjects(template ...Attribute) ([]Object, error) {
	return s.d.findObjects(s.handle, template)
}

// Attribute reads one attribute of an object.
func (s *Session) Attribute(obj Object, typ uint) ([]byte, error) {
	return s.d.attribute(s.handle, obj, typ)
}

// Sign signs data, normally a digest, with the token-held key in a single operation.
func (s *Session) Sign(mech Mechanism, key Object, data []byte) ([]byte, error) {
	return s.d.sign(s.handle, mech, key, data)
}

// CreateObject stores a new object described by template on the token.
func (s *Session) CreateObject(template ...Attribute) (Object, error) {
	return s.d.createObject(s.handle, template)
}

type driver interface {
	tokens() ([]Token, error)
	openSession(slot uint, readWrite bool) (uint, error)
	closeSession(session uint)
	login(session uint, pin []byte) error
	logout(session uint)
	findObjects(session uint, template []Attribute) ([]Object, error)
	attribute(session uint, obj Object, typ uint) ([]byte, error)
	sign(session uint, mech Mechanism, key Object, data []byte) ([]byte, error)
	createObject(session uint, template []Attribute) (Object, error)
}

// ulongSize is the width of CK_ULONG on the 64-bit platforms the driver builds for.
const ulongSize = 8

// ULong encodes an integer attribute value the way the module reads a CK_ULONG.
func ULong(v uint) []byte {
	return binary.NativeEndian.AppendUint64(nil, uint64(v))
}

func ulongValue(b []byte) (uint, error) {
	if len(b) != ulongSize {
		return 0, fmt.Errorf("CK_ULONG value has %d bytes", len(b))
	}
	return uint(binary.NativeEndian.Uint64(b)), nil
}
