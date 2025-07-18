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

func writeBytes(ctx context.Context, file string, err error, configDir string, configFileName string, bs []byte) error {
	if ctx.Err() != nil {
		return fmt.Errorf("write bytes start: %w", ctx.Err())
	}

	tempFile, err := os.CreateTemp(configDir, ".*"+configFileName)
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}

	tempFileName := tempFile.Name()

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

func openOrCreateFile(file string) (*os.File, error) {
	s, err := os.Stat(file)
	if err == nil {
		return os.OpenFile(file, os.O_WRONLY, s.Mode())
	}

	if !os.IsNotExist(err) {
		return nil, err
	}

	targetFile, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	//no:lint
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

// ReadJsonWithEnvSub reads JSON config file and maps to a provided interface with environment variable substitution
func ReadJsonWithEnvSub(file string, res interface{}) (interface{}, error) {
	envVars := getEnvMap()

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bs, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	t, err := template.New("").Parse(string(bs))
	if err != nil {
		return nil, fmt.Errorf("error parsing template: %v", err)
	}

	var output bytes.Buffer
	// Execute the template, substituting environment variables
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

// getEnvMap Convert the output of os.Environ() to a map
func getEnvMap() map[string]string {
	envMap := make(map[string]string)

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
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

func prepareConfigFileDir(file string) (string, string, error) {
	configDir, configFileName := filepath.Split(file)
	if configDir == "" {
		return filepath.Dir(file), configFileName, nil
	}

	err := os.MkdirAll(configDir, 0750)
	if err != nil {
		return "", "", err
	}

	return configDir, configFileName, err
}
