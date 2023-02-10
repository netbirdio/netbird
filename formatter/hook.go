package formatter

import (
	"fmt"
	"path"

	"github.com/sirupsen/logrus"
)

// ContextHook is a custom hook for add the source information for the entry
type ContextHook struct{}

// Levels set the supported levels for this hook
func (hook ContextHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire extend with the source information the entry.Data
func (hook ContextHook) Fire(entry *logrus.Entry) error {
	_, pkg := path.Split(path.Dir(entry.Caller.File))
	file := path.Base(entry.Caller.File)
	entry.Data["source"] = fmt.Sprintf("%s/%s:%v", pkg, file, entry.Caller.Line)
	return nil
}
