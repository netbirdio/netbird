package formatter

import (
	"fmt"
	"path"
	"runtime/debug"
	"strings"

	"github.com/sirupsen/logrus"
)

// ContextHook is a custom hook for add the source information for the entry
type ContextHook struct {
	goModuleName string
}

// NewContextHook instantiate a new context hook
func NewContextHook() *ContextHook {
	hook := &ContextHook{}
	hook.goModuleName = hook.moduleName() + "/"
	return hook
}

// Levels set the supported levels for this hook
func (hook ContextHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire extend with the source information the entry.Data
func (hook ContextHook) Fire(entry *logrus.Entry) error {
	src := hook.parseSrc(entry.Caller.File)
	entry.Data["source"] = fmt.Sprintf("%s:%v", src, entry.Caller.Line)
	return nil
}

func (hook ContextHook) moduleName() string {
	info, ok := debug.ReadBuildInfo()
	if ok && info.Main.Path != "" {
		return info.Main.Path
	}

	return "netbird"
}

func (hook ContextHook) parseSrc(filePath string) string {
	netbirdPath := strings.SplitAfter(filePath, hook.goModuleName)
	if len(netbirdPath) > 1 {
		return netbirdPath[len(netbirdPath)-1]
	}

	// in case of forked repo
	netbirdPath = strings.SplitAfter(filePath, "netbird/")
	if len(netbirdPath) > 1 {
		return netbirdPath[len(netbirdPath)-1]
	}

	// in case if log entry is come from external pkg
	_, pkg := path.Split(path.Dir(filePath))
	file := path.Base(filePath)
	return fmt.Sprintf("%s/%s", pkg, file)
}
