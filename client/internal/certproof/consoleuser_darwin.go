package certproof

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
	log "github.com/sirupsen/logrus"
)

const (
	systemConfigurationFramework = "/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration"

	encodingUTF8       = 0x08000100
	consoleNameBufSize = 256
)

var (
	consoleOnce sync.Once
	consoleErr  error

	scDynamicStoreCopyConsoleUser func(store uintptr, uid, gid *uint32) uintptr
	cfStringGetCString            func(str uintptr, buffer *byte, size int, encoding uint32) bool
)

// ConsoleUser is the account whose desktop session owns the display. Its login keychain
// is the only user keychain a NetBird daemon can reach, and only while it is logged in.
type ConsoleUser struct {
	Name string
	UID  uint32
	GID  uint32
}

// CurrentConsoleUser reports the user sitting at the desktop. The second return value is
// false when nobody is: at the login window macOS either reports no console user at all
// or attributes the session to root, and neither has a login keychain to offer.
func CurrentConsoleUser() (ConsoleUser, bool) {
	if err := loadConsoleUser(); err != nil {
		log.Infof("console user lookup unavailable: %v", err)
		return ConsoleUser{}, false
	}

	var uid, gid uint32
	name := scDynamicStoreCopyConsoleUser(0, &uid, &gid)
	if name == 0 {
		log.Info("no console user is logged in, no login keychain is reachable")
		return ConsoleUser{}, false
	}
	defer cfRelease(name)

	user := ConsoleUser{Name: cfString(name), UID: uid, GID: gid}
	if !user.hasDesktop() {
		log.Infof("console session belongs to %q uid=%d, which is not a desktop login, no login keychain is reachable", user.Name, user.UID)
		return ConsoleUser{}, false
	}
	return user, true
}

// hasDesktop reports whether the console session is a real user desktop. The login
// window runs as root and some macOS releases name it "loginwindow" instead.
func (u ConsoleUser) hasDesktop() bool {
	switch u.Name {
	case "", "root", "loginwindow":
		return false
	}
	return u.UID != 0
}

func cfString(str uintptr) string {
	buf := make([]byte, consoleNameBufSize)
	if !cfStringGetCString(str, &buf[0], len(buf), encodingUTF8) {
		return ""
	}
	if end := bytes.IndexByte(buf, 0); end >= 0 {
		return string(buf[:end])
	}
	return string(buf)
}

// loadConsoleUser resolves the console user symbols. It loads the keychain bindings
// first because CFRelease is resolved there and released strings depend on it.
func loadConsoleUser() error {
	if err := loadKeychain(); err != nil {
		return err
	}
	consoleOnce.Do(func() { consoleErr = resolveConsoleUser() })
	return consoleErr
}

func resolveConsoleUser() error {
	systemConfiguration, err := purego.Dlopen(systemConfigurationFramework, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("open %s: %w", systemConfigurationFramework, err)
	}
	coreFoundation, err := purego.Dlopen(coreFoundationFramework, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("open %s: %w", coreFoundationFramework, err)
	}

	symbol, err := purego.Dlsym(systemConfiguration, "SCDynamicStoreCopyConsoleUser")
	if err != nil {
		return fmt.Errorf("resolve SCDynamicStoreCopyConsoleUser: %w", err)
	}
	purego.RegisterFunc(&scDynamicStoreCopyConsoleUser, symbol)

	symbol, err = purego.Dlsym(coreFoundation, "CFStringGetCString")
	if err != nil {
		return fmt.Errorf("resolve CFStringGetCString: %w", err)
	}
	purego.RegisterFunc(&cfStringGetCString, symbol)
	return nil
}
