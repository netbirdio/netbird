package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"text/template"
)

// ExpandEnvTemplate substitutes Go-template references with environment values.
func ExpandEnvTemplate(data []byte) ([]byte, error) {
	tmpl, err := template.New("config").Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse environment template: %w", err)
	}

	var output bytes.Buffer
	if err := tmpl.Execute(&output, environmentMap()); err != nil {
		return nil, fmt.Errorf("execute environment template: %w", err)
	}
	return output.Bytes(), nil
}

func environmentMap() map[string]string {
	environment := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			environment[key] = value
		}
	}
	return environment
}
