package util

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

// WriteJson writes JSON config object to a file creating parent directories if required
// The output JSON is pretty-formatted
func WriteJson(file string, obj interface{}) error {

	configDir, configFileName, err := prepareConfigFileDir(file)
	if err != nil {
		return err
	}

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

// DirectWriteJson writes JSON config object to a file creating parent directories if required without creating a temporary file
func DirectWriteJson(file string, obj interface{}) error {

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
	return configDir, configFileName, err
}
