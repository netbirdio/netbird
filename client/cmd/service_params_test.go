//go:build !ios && !android

package cmd

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/configs"
)

func TestServiceParamsPath(t *testing.T) {
	original := configs.StateDir
	t.Cleanup(func() { configs.StateDir = original })

	configs.StateDir = "/var/lib/netbird"
	assert.Equal(t, filepath.Join("/var/lib/netbird", "service.json"), serviceParamsPath())

	configs.StateDir = "/custom/state"
	assert.Equal(t, filepath.Join("/custom/state", "service.json"), serviceParamsPath())
}

func TestSaveAndLoadServiceParams(t *testing.T) {
	tmpDir := t.TempDir()

	original := configs.StateDir
	t.Cleanup(func() { configs.StateDir = original })
	configs.StateDir = tmpDir

	params := &serviceParams{
		LogLevel:              "debug",
		DaemonAddr:            "unix:///var/run/netbird.sock",
		ManagementURL:         "https://my.server.com",
		ConfigPath:            "/etc/netbird/config.json",
		LogFiles:              []string{"/var/log/netbird/client.log", "console"},
		DisableProfiles:       true,
		DisableUpdateSettings: false,
		ServiceEnvVars:        map[string]string{"NB_LOG_FORMAT": "json", "CUSTOM": "val"},
	}

	err := saveServiceParams(params)
	require.NoError(t, err)

	// Verify the file exists and is valid JSON.
	data, err := os.ReadFile(filepath.Join(tmpDir, "service.json"))
	require.NoError(t, err)
	assert.True(t, json.Valid(data))

	loaded, err := loadServiceParams()
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, params.LogLevel, loaded.LogLevel)
	assert.Equal(t, params.DaemonAddr, loaded.DaemonAddr)
	assert.Equal(t, params.ManagementURL, loaded.ManagementURL)
	assert.Equal(t, params.ConfigPath, loaded.ConfigPath)
	assert.Equal(t, params.LogFiles, loaded.LogFiles)
	assert.Equal(t, params.DisableProfiles, loaded.DisableProfiles)
	assert.Equal(t, params.DisableUpdateSettings, loaded.DisableUpdateSettings)
	assert.Equal(t, params.ServiceEnvVars, loaded.ServiceEnvVars)
}

func TestLoadServiceParams_FileNotExists(t *testing.T) {
	tmpDir := t.TempDir()

	original := configs.StateDir
	t.Cleanup(func() { configs.StateDir = original })
	configs.StateDir = tmpDir

	params, err := loadServiceParams()
	assert.NoError(t, err)
	assert.Nil(t, params)
}

func TestLoadServiceParams_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()

	original := configs.StateDir
	t.Cleanup(func() { configs.StateDir = original })
	configs.StateDir = tmpDir

	err := os.WriteFile(filepath.Join(tmpDir, "service.json"), []byte("not json"), 0600)
	require.NoError(t, err)

	params, err := loadServiceParams()
	assert.Error(t, err)
	assert.Nil(t, params)
}

func TestCurrentServiceParams(t *testing.T) {
	origLogLevel := logLevel
	origDaemonAddr := daemonAddr
	origManagementURL := managementURL
	origConfigPath := configPath
	origLogFiles := logFiles
	origProfilesDisabled := profilesDisabled
	origUpdateSettingsDisabled := updateSettingsDisabled
	origServiceEnvVars := serviceEnvVars
	t.Cleanup(func() {
		logLevel = origLogLevel
		daemonAddr = origDaemonAddr
		managementURL = origManagementURL
		configPath = origConfigPath
		logFiles = origLogFiles
		profilesDisabled = origProfilesDisabled
		updateSettingsDisabled = origUpdateSettingsDisabled
		serviceEnvVars = origServiceEnvVars
	})

	logLevel = "trace"
	daemonAddr = "tcp://127.0.0.1:9999"
	managementURL = "https://mgmt.example.com"
	configPath = "/tmp/test-config.json"
	logFiles = []string{"/tmp/test.log"}
	profilesDisabled = true
	updateSettingsDisabled = true
	serviceEnvVars = []string{"FOO=bar", "BAZ=qux"}

	params := currentServiceParams()

	assert.Equal(t, "trace", params.LogLevel)
	assert.Equal(t, "tcp://127.0.0.1:9999", params.DaemonAddr)
	assert.Equal(t, "https://mgmt.example.com", params.ManagementURL)
	assert.Equal(t, "/tmp/test-config.json", params.ConfigPath)
	assert.Equal(t, []string{"/tmp/test.log"}, params.LogFiles)
	assert.True(t, params.DisableProfiles)
	assert.True(t, params.DisableUpdateSettings)
	assert.Equal(t, map[string]string{"FOO": "bar", "BAZ": "qux"}, params.ServiceEnvVars)
}

func TestApplyServiceParams_OnlyUnchangedFlags(t *testing.T) {
	origLogLevel := logLevel
	origDaemonAddr := daemonAddr
	origManagementURL := managementURL
	origConfigPath := configPath
	origLogFiles := logFiles
	origProfilesDisabled := profilesDisabled
	origUpdateSettingsDisabled := updateSettingsDisabled
	origServiceEnvVars := serviceEnvVars
	t.Cleanup(func() {
		logLevel = origLogLevel
		daemonAddr = origDaemonAddr
		managementURL = origManagementURL
		configPath = origConfigPath
		logFiles = origLogFiles
		profilesDisabled = origProfilesDisabled
		updateSettingsDisabled = origUpdateSettingsDisabled
		serviceEnvVars = origServiceEnvVars
	})

	// Reset all flags to defaults.
	logLevel = "info"
	daemonAddr = "unix:///var/run/netbird.sock"
	managementURL = ""
	configPath = "/etc/netbird/config.json"
	logFiles = []string{"/var/log/netbird/client.log"}
	profilesDisabled = false
	updateSettingsDisabled = false
	serviceEnvVars = nil

	// Reset Changed state on all relevant flags.
	rootCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		f.Changed = false
	})
	serviceCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		f.Changed = false
	})

	// Simulate user explicitly setting --log-level via CLI.
	logLevel = "warn"
	require.NoError(t, rootCmd.PersistentFlags().Set("log-level", "warn"))

	saved := &serviceParams{
		LogLevel:              "debug",
		DaemonAddr:            "tcp://127.0.0.1:5555",
		ManagementURL:         "https://saved.example.com",
		ConfigPath:            "/saved/config.json",
		LogFiles:              []string{"/saved/client.log"},
		DisableProfiles:       true,
		DisableUpdateSettings: true,
		ServiceEnvVars:        map[string]string{"SAVED_KEY": "saved_val"},
	}

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("service-env", nil, "")
	applyServiceParams(cmd, saved)

	// log-level was Changed, so it should keep "warn", not use saved "debug".
	assert.Equal(t, "warn", logLevel)

	// All other fields were not Changed, so they should use saved values.
	assert.Equal(t, "tcp://127.0.0.1:5555", daemonAddr)
	assert.Equal(t, "https://saved.example.com", managementURL)
	assert.Equal(t, "/saved/config.json", configPath)
	assert.Equal(t, []string{"/saved/client.log"}, logFiles)
	assert.True(t, profilesDisabled)
	assert.True(t, updateSettingsDisabled)
	assert.Equal(t, []string{"SAVED_KEY=saved_val"}, serviceEnvVars)
}

func TestApplyServiceParams_BooleanRevertToFalse(t *testing.T) {
	origProfilesDisabled := profilesDisabled
	origUpdateSettingsDisabled := updateSettingsDisabled
	t.Cleanup(func() {
		profilesDisabled = origProfilesDisabled
		updateSettingsDisabled = origUpdateSettingsDisabled
	})

	// Simulate current state where booleans are true (e.g. set by previous install).
	profilesDisabled = true
	updateSettingsDisabled = true

	// Reset Changed state so flags appear unset.
	serviceCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		f.Changed = false
	})

	// Saved params have both as false.
	saved := &serviceParams{
		DisableProfiles:       false,
		DisableUpdateSettings: false,
	}

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("service-env", nil, "")
	applyServiceParams(cmd, saved)

	assert.False(t, profilesDisabled, "saved false should override current true")
	assert.False(t, updateSettingsDisabled, "saved false should override current true")
}

func TestApplyServiceParams_ClearManagementURL(t *testing.T) {
	origManagementURL := managementURL
	t.Cleanup(func() { managementURL = origManagementURL })

	managementURL = "https://leftover.example.com"

	// Simulate saved params where management URL was explicitly cleared.
	saved := &serviceParams{
		LogLevel:   "info",
		DaemonAddr: "unix:///var/run/netbird.sock",
		// ManagementURL intentionally empty: was cleared with --management-url "".
	}

	rootCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		f.Changed = false
	})

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("service-env", nil, "")
	applyServiceParams(cmd, saved)

	assert.Equal(t, "", managementURL, "saved empty management URL should clear the current value")
}

func TestApplyServiceParams_NilParams(t *testing.T) {
	origLogLevel := logLevel
	t.Cleanup(func() { logLevel = origLogLevel })

	logLevel = "info"
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("service-env", nil, "")

	// Should be a no-op.
	applyServiceParams(cmd, nil)
	assert.Equal(t, "info", logLevel)
}

func TestApplyServiceEnvParams_MergeExplicitAndSaved(t *testing.T) {
	origServiceEnvVars := serviceEnvVars
	t.Cleanup(func() { serviceEnvVars = origServiceEnvVars })

	// Set up a command with --service-env marked as Changed.
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("service-env", nil, "")
	require.NoError(t, cmd.Flags().Set("service-env", "EXPLICIT=yes,OVERLAP=explicit"))

	serviceEnvVars = []string{"EXPLICIT=yes", "OVERLAP=explicit"}

	saved := &serviceParams{
		ServiceEnvVars: map[string]string{
			"SAVED":   "val",
			"OVERLAP": "saved",
		},
	}

	applyServiceEnvParams(cmd, saved)

	// Parse result for easier assertion.
	result, err := parseServiceEnvVars(serviceEnvVars)
	require.NoError(t, err)

	assert.Equal(t, "yes", result["EXPLICIT"])
	assert.Equal(t, "val", result["SAVED"])
	// Explicit wins on conflict.
	assert.Equal(t, "explicit", result["OVERLAP"])
}

func TestApplyServiceEnvParams_NotChanged(t *testing.T) {
	origServiceEnvVars := serviceEnvVars
	t.Cleanup(func() { serviceEnvVars = origServiceEnvVars })

	serviceEnvVars = nil

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("service-env", nil, "")

	saved := &serviceParams{
		ServiceEnvVars: map[string]string{"FROM_SAVED": "val"},
	}

	applyServiceEnvParams(cmd, saved)

	result, err := parseServiceEnvVars(serviceEnvVars)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"FROM_SAVED": "val"}, result)
}

// TestServiceParams_FieldsCoveredInFunctions ensures that all serviceParams fields are
// referenced in both currentServiceParams() and applyServiceParams(). If a new field is
// added to serviceParams but not wired into these functions, this test fails.
func TestServiceParams_FieldsCoveredInFunctions(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "service_params.go", nil, 0)
	require.NoError(t, err)

	// Collect all JSON field names from the serviceParams struct.
	structFields := extractStructJSONFields(t, file, "serviceParams")
	require.NotEmpty(t, structFields, "failed to find serviceParams struct fields")

	// Collect field names referenced in currentServiceParams and applyServiceParams.
	currentFields := extractFuncFieldRefs(t, file, "currentServiceParams", structFields)
	applyFields := extractFuncFieldRefs(t, file, "applyServiceParams", structFields)
	// applyServiceEnvParams handles ServiceEnvVars indirectly.
	applyEnvFields := extractFuncFieldRefs(t, file, "applyServiceEnvParams", structFields)
	for k, v := range applyEnvFields {
		applyFields[k] = v
	}

	for _, field := range structFields {
		assert.Contains(t, currentFields, field,
			"serviceParams field %q is not captured in currentServiceParams()", field)
		assert.Contains(t, applyFields, field,
			"serviceParams field %q is not restored in applyServiceParams()/applyServiceEnvParams()", field)
	}
}

// TestServiceParams_BuildArgsCoversAllFlags ensures that buildServiceArguments references
// all serviceParams fields that should become CLI args. ServiceEnvVars is excluded because
// it flows through newSVCConfig() EnvVars, not CLI args.
func TestServiceParams_BuildArgsCoversAllFlags(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "service_params.go", nil, 0)
	require.NoError(t, err)

	structFields := extractStructJSONFields(t, file, "serviceParams")
	require.NotEmpty(t, structFields)

	installerFile, err := parser.ParseFile(fset, "service_installer.go", nil, 0)
	require.NoError(t, err)

	// Fields that are handled outside of buildServiceArguments (env vars go through newSVCConfig).
	fieldsNotInArgs := map[string]bool{
		"ServiceEnvVars": true,
	}

	buildFields := extractFuncGlobalRefs(t, installerFile, "buildServiceArguments")

	// Forward: every struct field must appear in buildServiceArguments.
	for _, field := range structFields {
		if fieldsNotInArgs[field] {
			continue
		}
		globalVar := fieldToGlobalVar(field)
		assert.Contains(t, buildFields, globalVar,
			"serviceParams field %q (global %q) is not referenced in buildServiceArguments()", field, globalVar)
	}

	// Reverse: every service-related global used in buildServiceArguments must
	// have a corresponding serviceParams field. This catches a developer adding
	// a new flag to buildServiceArguments without adding it to the struct.
	globalToField := make(map[string]string, len(structFields))
	for _, field := range structFields {
		globalToField[fieldToGlobalVar(field)] = field
	}
	// Identifiers in buildServiceArguments that are not service params
	// (builtins, boilerplate, loop variables).
	nonParamGlobals := map[string]bool{
		"args": true, "append": true, "string": true, "_": true,
		"logFile": true, // range variable over logFiles
	}
	for ref := range buildFields {
		if nonParamGlobals[ref] {
			continue
		}
		_, inStruct := globalToField[ref]
		assert.True(t, inStruct,
			"buildServiceArguments() references global %q which has no corresponding serviceParams field", ref)
	}
}

// extractStructJSONFields returns field names from a named struct type.
func extractStructJSONFields(t *testing.T, file *ast.File, structName string) []string {
	t.Helper()
	var fields []string
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != structName {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, f := range st.Fields.List {
			if len(f.Names) > 0 {
				fields = append(fields, f.Names[0].Name)
			}
		}
		return false
	})
	return fields
}

// extractFuncFieldRefs returns which of the given field names appear inside the
// named function, either as selector expressions (params.FieldName) or as
// composite literal keys (&serviceParams{FieldName: ...}).
func extractFuncFieldRefs(t *testing.T, file *ast.File, funcName string, fields []string) map[string]bool {
	t.Helper()
	fieldSet := make(map[string]bool, len(fields))
	for _, f := range fields {
		fieldSet[f] = true
	}

	found := make(map[string]bool)
	fn := findFuncDecl(file, funcName)
	require.NotNil(t, fn, "function %s not found", funcName)

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if fieldSet[v.Sel.Name] {
				found[v.Sel.Name] = true
			}
		case *ast.KeyValueExpr:
			if ident, ok := v.Key.(*ast.Ident); ok && fieldSet[ident.Name] {
				found[ident.Name] = true
			}
		}
		return true
	})
	return found
}

// extractFuncGlobalRefs returns all identifier names referenced in the named function body.
func extractFuncGlobalRefs(t *testing.T, file *ast.File, funcName string) map[string]bool {
	t.Helper()
	fn := findFuncDecl(file, funcName)
	require.NotNil(t, fn, "function %s not found", funcName)

	refs := make(map[string]bool)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok {
			refs[ident.Name] = true
		}
		return true
	})
	return refs
}

func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// fieldToGlobalVar maps serviceParams field names to the package-level variable
// names used in buildServiceArguments and applyServiceParams.
func fieldToGlobalVar(field string) string {
	m := map[string]string{
		"LogLevel":              "logLevel",
		"DaemonAddr":            "daemonAddr",
		"ManagementURL":         "managementURL",
		"ConfigPath":            "configPath",
		"LogFiles":              "logFiles",
		"DisableProfiles":       "profilesDisabled",
		"DisableUpdateSettings": "updateSettingsDisabled",
		"ServiceEnvVars":        "serviceEnvVars",
	}
	if v, ok := m[field]; ok {
		return v
	}
	// Default: lowercase first letter.
	return strings.ToLower(field[:1]) + field[1:]
}

func TestEnvMapToSlice(t *testing.T) {
	m := map[string]string{"A": "1", "B": "2"}
	s := envMapToSlice(m)
	assert.Len(t, s, 2)
	assert.Contains(t, s, "A=1")
	assert.Contains(t, s, "B=2")
}

func TestEnvMapToSlice_Empty(t *testing.T) {
	s := envMapToSlice(map[string]string{})
	assert.Empty(t, s)
}
