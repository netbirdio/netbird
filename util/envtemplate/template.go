// Package envtemplate expands Go templates with environment variables.
package envtemplate

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"text/template"
)

// Expand substitutes Go-template references with environment values.
func Expand(data []byte) ([]byte, error) {
	tmpl, err := template.New("config").Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse environment template: %w", err)
	}

	var output bytes.Buffer
	if err := tmpl.Execute(&output, environment()); err != nil {
		return nil, fmt.Errorf("execute environment template: %w", err)
	}
	return output.Bytes(), nil
}

func environment() map[string]string {
	values := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	return values
}
