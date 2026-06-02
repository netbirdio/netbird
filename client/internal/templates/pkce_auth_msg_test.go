package templates

import (
	"html/template"
	"os"
	"path/filepath"
	"testing"
)

func TestPKCEAuthMsgTemplate(t *testing.T) {
	tests := []struct {
		name                 string
		data                 map[string]string
		outputFile           string
		expectedTitle        string
		expectedInContent    []string
		notExpectedInContent []string
	}{
		{
			name: "error_state",
			data: map[string]string{
				"Error": "authentication failed: invalid state",
			},
			outputFile:    "pkce-auth-error.html",
			expectedTitle: "Login Failed",
			expectedInContent: []string{
				"authentication failed: invalid state",
				"Login Failed",
			},
			notExpectedInContent: []string{
				"Login Successful",
				"Your device is now registered and logged in to NetBird",
			},
		},
		{
			name: "success_state",
			data: map[string]string{
				// No error field means success
			},
			outputFile:    "pkce-auth-success.html",
			expectedTitle: "Login Successful",
			expectedInContent: []string{
				"Login Successful",
				"Your device is now registered and logged in to NetBird. You can now close this window.",
			},
			notExpectedInContent: []string{
				"Login Failed",
			},
		},
		{
			name: "error_state_timeout",
			data: map[string]string{
				"Error": "authentication timeout: request expired after 5 minutes",
			},
			outputFile:    "pkce-auth-timeout.html",
			expectedTitle: "Login Failed",
			expectedInContent: []string{
				"authentication timeout: request expired after 5 minutes",
				"Login Failed",
			},
			notExpectedInContent: []string{
				"Login Successful",
				"Your device is now registered and logged in to NetBird",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the template
			tmpl, err := template.New("pkce-auth-msg").Parse(PKCEAuthMsgTmpl)
			if err != nil {
				t.Fatalf("Failed to parse template: %v", err)
			}

			// Create temp directory for this test
			tempDir := t.TempDir()
			outputPath := filepath.Join(tempDir, tt.outputFile)

			// Create output file
			file, err := os.Create(outputPath)
			if err != nil {
				t.Fatalf("Failed to create output file: %v", err)
			}

			// Execute the template
			if err := tmpl.Execute(file, tt.data); err != nil {
				file.Close()
				t.Fatalf("Failed to execute template: %v", err)
			}
			file.Close()

			t.Logf("Generated test output: %s", outputPath)

			// Read the generated file
			content, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatalf("Failed to read output file: %v", err)
			}

			contentStr := string(content)

			// Verify file has content
			if len(contentStr) == 0 {
				t.Error("Output file is empty")
			}

			// Verify basic HTML structure
			basicElements := []string{
				"<!DOCTYPE html>",
				"<html",
				"<head>",
				"<body>",
				"NetBird",
			}

			for _, elem := range basicElements {
				if !contains(contentStr, elem) {
					t.Errorf("Expected HTML to contain '%s', but it was not found", elem)
				}
			}

			// Verify expected title
			if !contains(contentStr, tt.expectedTitle) {
				t.Errorf("Expected HTML to contain title '%s', but it was not found", tt.expectedTitle)
			}

			// Verify expected content is present
			for _, expected := range tt.expectedInContent {
				if !contains(contentStr, expected) {
					t.Errorf("Expected HTML to contain '%s', but it was not found", expected)
				}
			}

			// Verify unexpected content is not present
			for _, notExpected := range tt.notExpectedInContent {
				if contains(contentStr, notExpected) {
					t.Errorf("Expected HTML to NOT contain '%s', but it was found", notExpected)
				}
			}
		})
	}
}

func TestPKCEAuthMsgTemplateValidation(t *testing.T) {
	// Test that the template can be parsed without errors
	tmpl, err := template.New("pkce-auth-msg").Parse(PKCEAuthMsgTmpl)
	if err != nil {
		t.Fatalf("Template parsing failed: %v", err)
	}

	// Test with empty data
	t.Run("empty_data", func(t *testing.T) {
		tempDir := t.TempDir()
		outputPath := filepath.Join(tempDir, "empty-data.html")

		file, err := os.Create(outputPath)
		if err != nil {
			t.Fatalf("Failed to create output file: %v", err)
		}
		defer file.Close()

		if err := tmpl.Execute(file, nil); err != nil {
			t.Errorf("Template execution with nil data failed: %v", err)
		}
	})

	// Test with error data
	t.Run("with_error", func(t *testing.T) {
		tempDir := t.TempDir()
		outputPath := filepath.Join(tempDir, "with-error.html")

		file, err := os.Create(outputPath)
		if err != nil {
			t.Fatalf("Failed to create output file: %v", err)
		}
		defer file.Close()

		data := map[string]string{
			"Error": "test error message",
		}
		if err := tmpl.Execute(file, data); err != nil {
			t.Errorf("Template execution with error data failed: %v", err)
		}
	})
}

func TestPKCEAuthMsgTemplateContent(t *testing.T) {
	// Test that the template contains expected elements
	tmpl, err := template.New("pkce-auth-msg").Parse(PKCEAuthMsgTmpl)
	if err != nil {
		t.Fatalf("Template parsing failed: %v", err)
	}

	t.Run("success_content", func(t *testing.T) {
		tempDir := t.TempDir()
		outputPath := filepath.Join(tempDir, "success.html")

		file, err := os.Create(outputPath)
		if err != nil {
			t.Fatalf("Failed to create output file: %v", err)
		}
		defer file.Close()

		data := map[string]string{}
		if err := tmpl.Execute(file, data); err != nil {
			t.Fatalf("Template execution failed: %v", err)
		}

		// Read the file and verify it contains expected content
		content, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("Failed to read output file: %v", err)
		}

		// Check for success indicators
		contentStr := string(content)
		if len(contentStr) == 0 {
			t.Error("Generated HTML is empty")
		}

		// Basic HTML structure checks
		requiredElements := []string{
			"<!DOCTYPE html>",
			"<html",
			"<head>",
			"<body>",
			"Login Successful",
			"NetBird",
		}

		for _, elem := range requiredElements {
			if !contains(contentStr, elem) {
				t.Errorf("Expected HTML to contain '%s', but it was not found", elem)
			}
		}
	})

	t.Run("error_content", func(t *testing.T) {
		tempDir := t.TempDir()
		outputPath := filepath.Join(tempDir, "error.html")

		file, err := os.Create(outputPath)
		if err != nil {
			t.Fatalf("Failed to create output file: %v", err)
		}
		defer file.Close()

		errorMsg := "test error message"
		data := map[string]string{
			"Error": errorMsg,
		}
		if err := tmpl.Execute(file, data); err != nil {
			t.Fatalf("Template execution failed: %v", err)
		}

		// Read the file and verify it contains expected content
		content, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("Failed to read output file: %v", err)
		}

		// Check for error indicators
		contentStr := string(content)
		if len(contentStr) == 0 {
			t.Error("Generated HTML is empty")
		}

		// Basic HTML structure checks
		requiredElements := []string{
			"<!DOCTYPE html>",
			"<html",
			"<head>",
			"<body>",
			"Login Failed",
			errorMsg,
		}

		for _, elem := range requiredElements {
			if !contains(contentStr, elem) {
				t.Errorf("Expected HTML to contain '%s', but it was not found", elem)
			}
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
