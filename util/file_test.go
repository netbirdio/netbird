package util

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type TestConfig struct {
	SomeMap   map[string]string
	SomeArray []string
	SomeField int
}

func TestConfigJSON(t *testing.T) {
	tests := []struct {
		name          string
		config        *TestConfig
		expectedError bool
	}{
		{
			name: "Valid JSON config",
			config: &TestConfig{
				SomeMap:   map[string]string{"key1": "value1", "key2": "value2"},
				SomeArray: []string{"value1", "value2"},
				SomeField: 99,
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			err := WriteJson(context.Background(), tmpDir+"/testconfig.json", tt.config)
			require.NoError(t, err)

			read, err := ReadJson(tmpDir+"/testconfig.json", &TestConfig{})
			require.NoError(t, err)
			require.NotNil(t, read)
			require.Equal(t, tt.config.SomeMap["key1"], read.(*TestConfig).SomeMap["key1"])
			require.Equal(t, tt.config.SomeMap["key2"], read.(*TestConfig).SomeMap["key2"])
			require.ElementsMatch(t, tt.config.SomeArray, read.(*TestConfig).SomeArray)
			require.Equal(t, tt.config.SomeField, read.(*TestConfig).SomeField)
		})
	}
}

func TestCopyFileContents(t *testing.T) {
	tests := []struct {
		name          string
		srcContent    []string
		expectedError bool
	}{
		{
			name:          "Copy file contents successfully",
			srcContent:    []string{"1", "2", "3"},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			src := tmpDir + "/copytest_src"
			dst := tmpDir + "/copytest_dst"

			err := WriteJson(context.Background(), src, tt.srcContent)
			require.NoError(t, err)

			err = CopyFileContents(src, dst)
			require.NoError(t, err)

			hashSrc := md5.New()
			hashDst := md5.New()

			srcFile, err := os.Open(src)
			require.NoError(t, err)
			defer func() {
				_ = srcFile.Close()
			}()

			dstFile, err := os.Open(dst)
			require.NoError(t, err)
			defer func() {
				_ = dstFile.Close()
			}()

			_, err = io.Copy(hashSrc, srcFile)
			require.NoError(t, err)

			_, err = io.Copy(hashDst, dstFile)
			require.NoError(t, err)

			require.Equal(t, hex.EncodeToString(hashSrc.Sum(nil)[:16]), hex.EncodeToString(hashDst.Sum(nil)[:16]))
		})
	}
}

func TestHandleConfigFileWithoutFullPath(t *testing.T) {
	tests := []struct {
		name          string
		config        *TestConfig
		expectedError bool
	}{
		{
			name: "Handle config file without full path",
			config: &TestConfig{
				SomeField: 123,
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgFile := "test_cfg.json"
			defer func() {
				_ = os.Remove(cfgFile)
			}()

			err := WriteJson(context.Background(), cfgFile, tt.config)
			require.NoError(t, err)

			read, err := ReadJson(cfgFile, &TestConfig{})
			require.NoError(t, err)
			require.NotNil(t, read)
		})
	}
}

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
