package util

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// WriteJson writes JSON config object to a file creating parent directories if required
// The output JSON is pretty-formatted
func WriteJson(file string, obj interface{}) error {

	configDir, configFileName := filepath.Split(file)
	err := os.MkdirAll(configDir, 0750)
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
