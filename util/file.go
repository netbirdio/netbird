package util

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	log "github.com/sirupsen/logrus"
)

// WriteJsonWithRestrictedPermission writes JSON config object to a file. Enforces permission on the parent directory
func WriteJsonWithRestrictedPermission(file string, obj interface{}) error {
	configDir, configFileName, err := prepareConfigFileDir(file)
	if err != nil {
		return err
	}

	err = EnforcePermission(file)
	if err != nil {
		return err
	}

	return writeJson(file, obj, configDir, configFileName)
}

// WriteJson writes JSON config object to a file creating parent directories if required
// The output JSON is pretty-formatted
func WriteJson(file string, obj interface{}) error {
	configDir, configFileName, err := prepareConfigFileDir(file)
	if err != nil {
		return err
	}

	return writeJson(file, obj, configDir, configFileName)
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

func writeJson(file string, obj interface{}, configDir string, configFileName string) error {

	// make it pretty
	bs, err := json.MarshalIndent(obj, "", "    ")
	if err != nil {
		return err
	}

	tempFile, err := os.CreateTemp(configDir, ".*"+configFileName)
	if err != nil {
		return err
	}

	tempFileName := tempFile.Name()
	// closing file ops as windows doesn't allow to move it
	err = tempFile.Close()
	if err != nil {
		return err
	}

	defer func() {
		_, err = os.Stat(tempFileName)
		if err == nil {
			os.Remove(tempFileName)
		}
	}()

	err = os.WriteFile(tempFileName, bs, 0600)
	if err != nil {
		return err
	}

	err = os.Rename(tempFileName, file)
	if err != nil {
		return err
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
