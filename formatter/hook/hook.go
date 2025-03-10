package hook

import (
	"fmt"
	"path"
	"runtime/debug"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/context"
)

type ExecutionContext string

const (
	ExecutionContextKey = "executionContext"

	HTTPSource   ExecutionContext = "HTTP"
	GRPCSource   ExecutionContext = "GRPC"
	SystemSource ExecutionContext = "SYSTEM"
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
	entry.Data[EntryKeySource] = fmt.Sprintf("%s:%v", src, entry.Caller.Line)
	additionalEntries(entry)

	if entry.Context == nil {
		return nil
	}

	source, ok := entry.Context.Value(ExecutionContextKey).(ExecutionContext)
	if !ok {
		return nil
	}

	entry.Data["context"] = source

	switch source {
	case HTTPSource:
		addHTTPFields(entry)
	case GRPCSource:
		addGRPCFields(entry)
	case SystemSource:
		addSystemFields(entry)
	}

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

func addHTTPFields(entry *logrus.Entry) {
	if ctxReqID, ok := entry.Context.Value(context.RequestIDKey).(string); ok {
		entry.Data[context.RequestIDKey] = ctxReqID
	}
	if ctxAccountID, ok := entry.Context.Value(context.AccountIDKey).(string); ok {
		entry.Data[context.AccountIDKey] = ctxAccountID
	}
	if ctxInitiatorID, ok := entry.Context.Value(context.UserIDKey).(string); ok {
		entry.Data[context.UserIDKey] = ctxInitiatorID
	}
}

func addGRPCFields(entry *logrus.Entry) {
	if ctxReqID, ok := entry.Context.Value(context.RequestIDKey).(string); ok {
		entry.Data[context.RequestIDKey] = ctxReqID
	}
	if ctxAccountID, ok := entry.Context.Value(context.AccountIDKey).(string); ok {
		entry.Data[context.AccountIDKey] = ctxAccountID
	}
	if ctxDeviceID, ok := entry.Context.Value(context.PeerIDKey).(string); ok {
		entry.Data[context.PeerIDKey] = ctxDeviceID
	}
}

func addSystemFields(entry *logrus.Entry) {
	if ctxReqID, ok := entry.Context.Value(context.RequestIDKey).(string); ok {
		entry.Data[context.RequestIDKey] = ctxReqID
	}
	if ctxInitiatorID, ok := entry.Context.Value(context.UserIDKey).(string); ok {
		entry.Data[context.UserIDKey] = ctxInitiatorID
	}
	if ctxAccountID, ok := entry.Context.Value(context.AccountIDKey).(string); ok {
		entry.Data[context.AccountIDKey] = ctxAccountID
	}
	if ctxDeviceID, ok := entry.Context.Value(context.PeerIDKey).(string); ok {
		entry.Data[context.PeerIDKey] = ctxDeviceID
	}
}
