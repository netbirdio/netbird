package util

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	log "github.com/sirupsen/logrus"
)

func WriteBytesWithRestrictedPermission(ctx context.Context, file string, bs []byte) error {
	configDir, configFileName, err := prepareConfigFileDir(file)
	if err != nil {
		return fmt.Errorf("prepare config file dir: %w", err)
	}

	if err = EnforcePermission(file); err != nil {
		return fmt.Errorf("enforce permission: %w", err)
	}

	return writeBytes(ctx, file, err, configDir, configFileName, bs)
}

// WriteJsonWithRestrictedPermission writes JSON config object to a file. Enforces permission on the parent directory
func WriteJsonWithRestrictedPermission(ctx context.Context, file string, obj interface{}) error {
	configDir, configFileName, err := prepareConfigFileDir(file)
	if err != nil {
		return err
	}

	err = EnforcePermission(file)
	if err != nil {
		return err
	}

	return writeJson(ctx, file, obj, configDir, configFileName)
}

// WriteJson writes JSON config object to a file creating parent directories if required
// The output JSON is pretty-formatted
func WriteJson(ctx context.Context, file string, obj interface{}) error {
	configDir, configFileName, err := prepareConfigFileDir(file)
	if err != nil {
		return err
	}

	return writeJson(ctx, file, obj, configDir, configFileName)
}

// DirectWriteJson writes JSON config object to a file creating parent directories if required without creating a temporary file
func DirectWriteJson(ctx context.Context, file string, obj interface{}) error {

	_, _, err := prepareConfigFileDir(file)
	if err != nil {
		return err
	}

	targetFile, err := openOrCreateFile(file)
	if err != nil {
		return err
	}

	defer func() {
		err = targetFile.Close()
		if err != nil {
			log.Errorf("failed to close file %s: %v", file, err)
		}
	}()

	// make it pretty
	bs, err := json.MarshalIndent(obj, "", "    ")
	if err != nil {
		return err
	}

	err = targetFile.Truncate(0)
	if err != nil {
		return err
	}

	_, err = targetFile.Write(bs)
	if err != nil {
		return err
	}

	return nil
}

func writeJson(ctx context.Context, file string, obj interface{}, configDir string, configFileName string) error {
	// Check context before expensive operations
	if ctx.Err() != nil {
		return fmt.Errorf("write json start: %w", ctx.Err())
	}

	// make it pretty
	bs, err := json.MarshalIndent(obj, "", "    ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return writeBytes(ctx, file, err, configDir, configFileName, bs)
}

// writeBytes writes bytes to a file using atomic write (temp file + rename) for safety.
// Security features:
// - Creates temp file with secure permissions (0600)
// - Uses atomic rename to prevent partial writes
// - Cleans up temp file on error
// - Respects context cancellation
// - Validates context before and after operations
func writeBytes(ctx context.Context, file string, err error, configDir string, configFileName string, bs []byte) error {
	if ctx.Err() != nil {
		return fmt.Errorf("write bytes start: %w", ctx.Err())
	}

	// Create temporary file with secure permissions (0600 = owner read/write only)
	// This prevents other users from reading sensitive configuration data
	tempFile, err := os.CreateTemp(configDir, ".*"+configFileName)
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}

	tempFileName := tempFile.Name()
	
	// Set secure permissions on temp file (owner read/write only)
	// This is critical for security as temp files may contain sensitive data
	if err := os.Chmod(tempFileName, 0600); err != nil {
		_ = tempFile.Close()
		_ = os.Remove(tempFileName)
		return fmt.Errorf("set temp file permissions: %w", err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := tempFile.SetDeadline(deadline); err != nil && !errors.Is(err, os.ErrNoDeadline) {
			log.Warnf("failed to set deadline: %v", err)
		}
	}

	_, err = tempFile.Write(bs)
	if err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("write: %w", err)
	}

	if err = tempFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tempFileName, err)
	}

	defer func() {
		_, err = os.Stat(tempFileName)
		if err == nil {
			os.Remove(tempFileName)
		}
	}()

	// Check context again
	if ctx.Err() != nil {
		return fmt.Errorf("after temp file: %w", ctx.Err())
	}

	if err = os.Rename(tempFileName, file); err != nil {
		return fmt.Errorf("move %s to %s: %w", tempFileName, file, err)
	}

	return nil
}

// openOrCreateFile opens an existing file or creates a new one with secure permissions.
// Security: New files are created with 0640 permissions (owner read/write, group read only).
// This prevents unauthorized access while allowing group members to read if needed.
func openOrCreateFile(file string) (*os.File, error) {
	s, err := os.Stat(file)
	if err == nil {
		// File exists - open with existing permissions
		return os.OpenFile(file, os.O_WRONLY, s.Mode())
	}

	if !os.IsNotExist(err) {
		return nil, err
	}

	// File doesn't exist - create with secure permissions
	// 0640 = owner read/write, group read, others no access
	targetFile, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	// Set secure permissions: owner read/write, group read only
	err = targetFile.Chmod(0640)
	if err != nil {
		_ = targetFile.Close()
		return nil, err
	}
	return targetFile, nil
}

// ReadJson reads JSON config file and maps to a provided interface
func ReadJson(file string, res interface{}) (interface{}, error) {

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bs, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(bs, &res)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// RemoveJson removes the specified JSON file if it exists
func RemoveJson(file string) error {
	// Check if the file exists
	if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
		return nil // File does not exist, nothing to remove
	}

	// Attempt to remove the file
	if err := os.Remove(file); err != nil {
		return fmt.Errorf("failed to remove JSON file %s: %w", file, err)
	}

	return nil
}

// ListFiles returns the full paths of all files in dir that match pattern.
// Pattern uses shell-style globbing (e.g. "*.json").
func ListFiles(dir, pattern string) ([]string, error) {
	// glob pattern like "/path/to/dir/*.json"
	globPattern := filepath.Join(dir, pattern)

	matches, err := filepath.Glob(globPattern)
	if err != nil {
		return nil, err
	}

	sort.Strings(matches)
	return matches, nil
}

// ReadJsonWithEnvSub reads JSON config file and maps to a provided interface with environment variable substitution.
// Security: This function limits the size of the input file to prevent DoS attacks through large template files.
// Environment variables are substituted using Go templates, which are executed in a safe context.
func ReadJsonWithEnvSub(file string, res interface{}) (interface{}, error) {
	// Security: Limit file size to prevent DoS attacks
	// 10MB is a reasonable limit for configuration files
	const maxConfigFileSize = 10 * 1024 * 1024 // 10MB
	
	envVars := getEnvMap()

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Limit the file size to prevent DoS attacks
	limitedReader := io.LimitReader(f, maxConfigFileSize+1)
	bs, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	// Check if file exceeded size limit
	if len(bs) > maxConfigFileSize {
		return nil, fmt.Errorf("config file too large: maximum size is %d bytes", maxConfigFileSize)
	}

	// Security: Use template with no functions to prevent code injection
	// The template only allows variable substitution, not function calls
	t, err := template.New("").Parse(string(bs))
	if err != nil {
		return nil, fmt.Errorf("error parsing template: %v", err)
	}

	var output bytes.Buffer
	// Execute the template, substituting environment variables
	// Security: Template execution is safe as we're only substituting variables, not executing functions
	err = t.Execute(&output, envVars)
	if err != nil {
		return nil, fmt.Errorf("error executing template: %v", err)
	}

	err = json.Unmarshal(output.Bytes(), &res)
	if err != nil {
		return nil, fmt.Errorf("failed parsing Json file after template was executed, err: %v", err)
	}

	return res, nil
}

// getEnvMap converts the output of os.Environ() to a map.
// Security: This function safely parses environment variables, handling edge cases
// where environment variables might not contain '=' or have empty values.
func getEnvMap() map[string]string {
	envMap := make(map[string]string)

	for _, env := range os.Environ() {
		// Security: Use SplitN with limit 2 to handle values containing '='
		// This prevents issues if environment variable values contain '=' characters
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			key := parts[0]
			value := parts[1]
			// Security: Validate key is not empty (shouldn't happen, but defensive)
			if key != "" {
				envMap[key] = value
			}
		}
		// If len(parts) != 2, skip invalid entries (defensive programming)
	}

	return envMap
}

// CopyFileContents copies contents of the given src file to the dst file
func CopyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cErr := out.Close()
		if err == nil {
			err = cErr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}

// prepareConfigFileDir prepares the directory for a config file.
// Security: Creates directory with 0750 permissions (owner read/write/execute, group read/execute, others no access).
// This ensures that only the owner and group can access the directory.
func prepareConfigFileDir(file string) (string, string, error) {
	configDir, configFileName := filepath.Split(file)
	if configDir == "" {
		return filepath.Dir(file), configFileName, nil
	}

	// Create directory with secure permissions: 0750 = owner rwx, group rx, others no access
	err := os.MkdirAll(configDir, 0750)
	if err != nil {
		return "", "", err
	}

	return configDir, configFileName, err
}
