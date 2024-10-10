package util

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestReadJsonWithEnvSub(t *testing.T) {
	type Config struct {
		CertFile     string `json:"CertFile"`
		Credentials  string `json:"Credentials"`
		NestedOption struct {
			URL string `json:"URL"`
		} `json:"NestedOption"`
	}

	type testCase struct {
		name           string
		envVars        map[string]string
		jsonTemplate   string
		expectedResult Config
		expectError    bool
		errorContains  string
	}

	tests := []testCase{
		{
			name: "All environment variables set",
			envVars: map[string]string{
				"CERT_FILE":   "/etc/certs/env_cert.crt",
				"CREDENTIALS": "env_credentials",
				"URL":         "https://env.testing.com",
			},
			jsonTemplate: `{
			  "CertFile": "{{ .CERT_FILE }}",
			  "Credentials": "{{ .CREDENTIALS }}",
			  "NestedOption": {
				   "URL": "{{ .URL }}"
			  }
			}`,
			expectedResult: Config{
				CertFile:    "/etc/certs/env_cert.crt",
				Credentials: "env_credentials",
				NestedOption: struct {
					URL string `json:"URL"`
				}{
					URL: "https://env.testing.com",
				},
			},
			expectError: false,
		},
		{
			name: "Missing environment variable",
			envVars: map[string]string{
				"CERT_FILE":   "/etc/certs/env_cert.crt",
				"CREDENTIALS": "env_credentials",
				// "URL" is intentionally missing
			},
			jsonTemplate: `{
			  "CertFile": "{{ .CERT_FILE }}",
			  "Credentials": "{{ .CREDENTIALS }}",
			  "NestedOption": {
				   "URL": "{{ .URL }}"
			  }
			}`,
			expectedResult: Config{
				CertFile:    "/etc/certs/env_cert.crt",
				Credentials: "env_credentials",
				NestedOption: struct {
					URL string `json:"URL"`
				}{
					URL: "<no value>",
				},
			},
			expectError: false,
		},
		{
			name: "Invalid JSON template",
			envVars: map[string]string{
				"CERT_FILE":   "/etc/certs/env_cert.crt",
				"CREDENTIALS": "env_credentials",
				"URL":         "https://env.testing.com",
			},
			jsonTemplate: `{
			  "CertFile": "{{ .CERT_FILE }}",
			  "Credentials": "{{ .CREDENTIALS }",
			  "NestedOption": {
				   "URL": "{{ .URL }}"
			  }
			}`, // Note the missing closing brace in "{{ .CREDENTIALS }"
			expectedResult: Config{},
			expectError:    true,
			errorContains:  "unexpected \"}\" in operand",
		},
		{
			name: "No substitutions",
			envVars: map[string]string{
				"CERT_FILE":   "/etc/certs/env_cert.crt",
				"CREDENTIALS": "env_credentials",
				"URL":         "https://env.testing.com",
			},
			jsonTemplate: `{
			  "CertFile": "/etc/certs/cert.crt",
			  "Credentials": "admnlknflkdasdf",
			  "NestedOption" : {
				   "URL": "https://testing.com"
			  }
			}`,
			expectedResult: Config{
				CertFile:    "/etc/certs/cert.crt",
				Credentials: "admnlknflkdasdf",
				NestedOption: struct {
					URL string `json:"URL"`
				}{
					URL: "https://testing.com",
				},
			},
			expectError: false,
		},
		{
			name: "Should fail when Invalid characters in variables",
			envVars: map[string]string{
				"CERT_FILE":   `"/etc/certs/"cert".crt"`,
				"CREDENTIALS": `env_credentia{ls}`,
				"URL":         `https://env.testing.com?param={{value}}`,
			},
			jsonTemplate: `{
			  "CertFile": "{{ .CERT_FILE }}",
			  "Credentials": "{{ .CREDENTIALS }}",
			  "NestedOption": {
				   "URL": "{{ .URL }}"
			  }
			}`,
			expectedResult: Config{
				CertFile:    `"/etc/certs/"cert".crt"`,
				Credentials: `env_credentia{ls}`,
				NestedOption: struct {
					URL string `json:"URL"`
				}{
					URL: `https://env.testing.com?param={{value}}`,
				},
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.envVars {
				t.Setenv(key, value)
			}

			tempFile, err := os.CreateTemp("", "config*.json")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}

			defer func() {
				err = os.Remove(tempFile.Name())
				if err != nil {
					t.Logf("Failed to remove temp file: %v", err)
				}
			}()

			_, err = tempFile.WriteString(tc.jsonTemplate)
			if err != nil {
				t.Fatalf("Failed to write to temp file: %v", err)
			}
			err = tempFile.Close()
			if err != nil {
				t.Fatalf("Failed to close temp file: %v", err)
			}

			var result Config

			_, err = ReadJsonWithEnvSub(tempFile.Name(), &result)

			if tc.expectError {
				if err == nil {
					t.Fatalf("Expected error but got none")
				}
				if !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("Expected error containing '%s', but got '%v'", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("ReadJsonWithEnvSub failed: %v", err)
				}
				if !reflect.DeepEqual(result, tc.expectedResult) {
					t.Errorf("Result does not match expected.\nGot: %+v\nExpected: %+v", result, tc.expectedResult)
				}
			}
		})
	}
}
