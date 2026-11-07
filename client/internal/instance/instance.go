// Package instance derives every machine-wide identifier of a NetBird client
// installation from its installation name.
//
// The default installation has an empty name, and every identifier it returns is
// the value NetBird used before named installations existed. A named
// installation qualifies the product token with "_<name>" (Netbird_acme,
// NetBird_acme-Match-0, 99-netbird_acme.conf), which no default identifier
// contains, so the default installation's prefix matchers never see a named
// installation's resources.
package instance

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
)

// Name is the canonical installation name: lowercase, empty for the default
// installation.
type Name string

const (
	// DefaultName is the name of the default installation.
	DefaultName Name = ""

	// defaultAlias addresses the default installation explicitly, for scripts
	// that run with NB_INSTANCE set.
	defaultAlias = "default"

	maxNameLen = 12
)

// ErrNamedUnsupported is returned for a named installation on a platform that
// supports only the default installation.
var ErrNamedUnsupported = errors.New("named installations are supported on Windows only")

var reservedNames = map[Name]struct{}{
	defaultAlias: {},
	"netbird":    {},
}

// Instance is one installation of the NetBird client. Its zero value is not
// valid; use Default or For.
type Instance struct {
	name   Name
	label  string
	role   Role
	goos   string
	getenv func(string) string
}

var (
	current atomic.Pointer[Instance]

	hooksMu sync.Mutex
	hooks   []func(Instance)
)

// Default returns the default installation for the running platform.
func Default() Instance {
	return newInstance(runtime.GOOS, os.Getenv, DefaultName, "")
}

// For returns the installation addressed by input: empty or "default" select the
// default installation, anything else must be a valid name. Named installations
// exist only on Windows.
func For(input string) (Instance, error) {
	name, label, err := ParseName(input)
	if err != nil {
		return Instance{}, err
	}
	if name != DefaultName && runtime.GOOS != "windows" {
		return Instance{}, ErrNamedUnsupported
	}
	return newInstance(runtime.GOOS, os.Getenv, name, label), nil
}

// ForPlatform is For for another platform, so tools and tests can derive the
// identifiers of a Windows installation on any host. It reads the environment
// of the running process.
func ForPlatform(goos, input string) (Instance, error) {
	name, label, err := ParseName(input)
	if err != nil {
		return Instance{}, err
	}
	if name != DefaultName && goos != goosWindows {
		return Instance{}, ErrNamedUnsupported
	}
	return newInstance(goos, os.Getenv, name, label), nil
}

// Current returns the installation this process runs as: the default one until
// SetCurrent is called.
func Current() Instance {
	if p := current.Load(); p != nil {
		return *p
	}
	return Default()
}

// SetCurrent makes inst the installation this process runs as. Packages that
// keep a derived value in a package variable register with OnSetCurrent and
// recompute it here. Call it once, before anything uses those values.
func SetCurrent(inst Instance) {
	hooksMu.Lock()
	defer hooksMu.Unlock()
	current.Store(&inst)
	for _, fn := range hooks {
		fn(inst)
	}
}

// OnSetCurrent registers fn to run with the new installation whenever
// SetCurrent is called.
func OnSetCurrent(fn func(Instance)) {
	hooksMu.Lock()
	defer hooksMu.Unlock()
	hooks = append(hooks, fn)
}

func newInstance(goos string, getenv func(string) string, name Name, label string) Instance {
	inst := Instance{name: name, goos: goos, getenv: getenv, role: RolePrimary}
	if name != DefaultName {
		inst.role = RoleSecondary
		inst.label = string(name)
		if isLabelOf(label, name) {
			inst.label = label
		}
	}
	return inst
}

// ParseName turns user input into a canonical name and a display label. Empty
// input and "default" (in any case) select the default installation.
func ParseName(input string) (Name, string, error) {
	if input == "" || asciiLower(input) == defaultAlias {
		return DefaultName, "", nil
	}
	if err := ValidateName(input); err != nil {
		return DefaultName, "", err
	}
	return Name(asciiLower(input)), input, nil
}

// ValidateName checks a name for a named installation and returns the message
// the installer and the CLI show for it.
func ValidateName(input string) error {
	if input == "" {
		return errors.New("Enter a name for this installation.") //nolint:staticcheck // user-facing message
	}
	lower := asciiLower(input)
	for i := 0; i < len(lower); i++ {
		if !isLetter(lower[i]) && !isDigit(lower[i]) {
			return errors.New("Use only letters and digits (no spaces, hyphens or underscores).") //nolint:staticcheck // user-facing message
		}
	}
	if !isLetter(lower[0]) {
		return errors.New("The name must start with a letter.") //nolint:staticcheck // user-facing message
	}
	if len(lower) > maxNameLen {
		return fmt.Errorf("The name can be at most %d characters long.", maxNameLen) //nolint:staticcheck // user-facing message
	}
	if _, ok := reservedNames[Name(lower)]; ok {
		return fmt.Errorf("%q is reserved. Choose another name.", lower) //nolint:staticcheck // user-facing message
	}
	return nil
}

// Name returns the canonical name, empty for the default installation.
func (i Instance) Name() Name {
	return i.name
}

// IsDefault reports whether this is the default installation.
func (i Instance) IsDefault() bool {
	return i.name == DefaultName
}

// Label returns the name as the user typed it, for display. It is empty for the
// default installation.
func (i Instance) Label() string {
	return i.label
}

// WithLabel returns the installation with a display label read from elsewhere,
// such as the installation record. A label that is not the name in another case
// is untrusted input and is ignored.
func (i Instance) WithLabel(label string) Instance {
	if !i.IsDefault() && isLabelOf(label, i.name) {
		i.label = label
	}
	return i
}

// Role returns the conflict role. The default installation is always primary.
func (i Instance) Role() Role {
	return i.role
}

// WithRole returns the installation with the given role. The default
// installation stays primary.
func (i Instance) WithRole(r Role) Instance {
	if !i.IsDefault() {
		i.role = r
	}
	return i
}

func isLabelOf(label string, name Name) bool {
	return label != "" && Name(asciiLower(label)) == name
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func isLetter(c byte) bool {
	return c >= 'a' && c <= 'z'
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
