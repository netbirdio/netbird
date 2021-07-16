package util

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
)

// WriteJson writes JSON config object to a file creating parent directories if required
// The output JSON is pretty-formatted
func WriteJson(file string, obj interface{}) error {

	configDir := filepath.Dir(file)
	err := os.MkdirAll(configDir, 0750)
	if err != nil {
		return err
	}

	// make it pretty
	bs, err := json.MarshalIndent(obj, "", "    ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(file, bs, 0600)
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

	bs, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(bs, &res)
	if err != nil {
		return nil, err
	}

	return res, nil
}
