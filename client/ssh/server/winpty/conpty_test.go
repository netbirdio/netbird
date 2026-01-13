//go:build windows

package winpty

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestBuildShellArgs(t *testing.T) {
	tests := []struct {
		name     string
		shell    string
		command  string
		expected []string
	}{
		{
			name:     "Shell with command",
			shell:    "powershell.exe",
			command:  "Get-Process",
			expected: []string{"powershell.exe", "-Command", "Get-Process"},
		},
		{
			name:     "CMD with command",
			shell:    "cmd.exe",
			command:  "dir",
			expected: []string{"cmd.exe", "-Command", "dir"},
		},
		{
			name:     "Shell interactive",
			shell:    "powershell.exe",
			command:  "",
			expected: []string{"powershell.exe"},
		},
		{
			name:     "CMD interactive",
			shell:    "cmd.exe",
			command:  "",
			expected: []string{"cmd.exe"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildShellArgs(tt.shell, tt.command)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildCommandLine(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "Simple args",
			args:     []string{"cmd.exe", "/c", "echo"},
			expected: "cmd.exe /c echo",
		},
		{
			name:     "Args with spaces",
			args:     []string{"Program Files\\app.exe", "arg with spaces"},
			expected: `"Program Files\app.exe" "arg with spaces"`,
		},
		{
			name:     "Args with quotes",
			args:     []string{"cmd.exe", "/c", `echo "hello world"`},
			expected: `cmd.exe /c "echo \"hello world\""`,
		},
		{
			name:     "PowerShell calling PowerShell",
			args:     []string{"powershell.exe", "-Command", `powershell.exe -Command "Get-Process | Where-Object {$_.Name -eq 'notepad'}"`},
			expected: `powershell.exe -Command "powershell.exe -Command \"Get-Process | Where-Object {$_.Name -eq 'notepad'}\""`,
		},
		{
			name:     "Complex nested quotes",
			args:     []string{"cmd.exe", "/c", `echo "He said \"Hello\" to me"`},
			expected: `cmd.exe /c "echo \"He said \\\"Hello\\\" to me\""`,
		},
		{
			name:     "Path with spaces and args",
			args:     []string{`C:\Program Files\MyApp\app.exe`, "--config", `C:\My Config\settings.json`},
			expected: `"C:\Program Files\MyApp\app.exe" --config "C:\My Config\settings.json"`,
		},
		{
			name:     "Empty argument",
			args:     []string{"cmd.exe", "/c", "echo", ""},
			expected: `cmd.exe /c echo ""`,
		},
		{
			name:     "Argument with backslashes",
			args:     []string{"robocopy", `C:\Source\`, `C:\Dest\`, "/E"},
			expected: `robocopy C:\Source\ C:\Dest\ /E`,
		},
		{
			name:     "Empty args",
			args:     []string{},
			expected: "",
		},
		{
			name:     "Single arg with space",
			args:     []string{"path with spaces"},
			expected: `"path with spaces"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildCommandLine(tt.args)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCreateConPtyPipes(t *testing.T) {
	inputRead, inputWrite, outputRead, outputWrite, err := createConPtyPipes()
	require.NoError(t, err, "Should create ConPty pipes successfully")

	// Verify all handles are valid
	assert.NotEqual(t, windows.InvalidHandle, inputRead, "Input read handle should be valid")
	assert.NotEqual(t, windows.InvalidHandle, inputWrite, "Input write handle should be valid")
	assert.NotEqual(t, windows.InvalidHandle, outputRead, "Output read handle should be valid")
	assert.NotEqual(t, windows.InvalidHandle, outputWrite, "Output write handle should be valid")

	// Clean up handles
	closeHandles(inputRead, inputWrite, outputRead, outputWrite)
}

func TestCreateConPty(t *testing.T) {
	inputRead, inputWrite, outputRead, outputWrite, err := createConPtyPipes()
	require.NoError(t, err, "Should create ConPty pipes successfully")
	defer closeHandles(inputRead, inputWrite, outputRead, outputWrite)

	hPty, err := createConPty(80, 24, inputRead, outputWrite)
	require.NoError(t, err, "Should create ConPty successfully")
	assert.NotEqual(t, windows.InvalidHandle, hPty, "ConPty handle should be valid")

	// Clean up ConPty
	ret, _, _ := procClosePseudoConsole.Call(uintptr(hPty))
	assert.NotEqual(t, uintptr(0), ret, "Should close ConPty successfully")
}

func TestConvertEnvironmentToUTF16(t *testing.T) {
	tests := []struct {
		name     string
		userEnv  []string
		hasError bool
	}{
		{
			name:     "Valid environment variables",
			userEnv:  []string{"PATH=C:\\Windows", "USER=testuser", "HOME=C:\\Users\\testuser"},
			hasError: false,
		},
		{
			name:     "Empty environment",
			userEnv:  []string{},
			hasError: false,
		},
		{
			name:     "Environment with empty strings",
			userEnv:  []string{"PATH=C:\\Windows", "", "USER=testuser"},
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := convertEnvironmentToUTF16(tt.userEnv)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if len(tt.userEnv) == 0 {
					assert.Nil(t, result, "Empty environment should return nil")
				} else {
					assert.NotNil(t, result, "Non-empty environment should return valid pointer")
				}
			}
		})
	}
}

func TestDuplicateToPrimaryToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping token tests in short mode")
	}

	// Get current process token for testing
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &token)
	require.NoError(t, err, "Should open current process token")
	defer func() {
		if err := windows.CloseHandle(windows.Handle(token)); err != nil {
			t.Logf("Failed to close token: %v", err)
		}
	}()

	primaryToken, err := duplicateToPrimaryToken(windows.Handle(token))
	require.NoError(t, err, "Should duplicate token to primary")
	assert.NotEqual(t, windows.InvalidHandle, primaryToken, "Primary token should be valid")

	// Clean up
	err = windows.CloseHandle(primaryToken)
	assert.NoError(t, err, "Should close primary token")
}

func TestWindowsHandleReader(t *testing.T) {
	// Create a pipe for testing
	var readHandle, writeHandle windows.Handle
	err := windows.CreatePipe(&readHandle, &writeHandle, nil, 0)
	require.NoError(t, err, "Should create pipe for testing")
	defer closeHandles(readHandle, writeHandle)

	// Write test data
	testData := []byte("Hello, Windows Handle Reader!")
	var bytesWritten uint32
	err = windows.WriteFile(writeHandle, testData, &bytesWritten, nil)
	require.NoError(t, err, "Should write test data")
	require.Equal(t, uint32(len(testData)), bytesWritten, "Should write all test data")

	// Close write handle to signal EOF
	if err := windows.CloseHandle(writeHandle); err != nil {
		t.Fatalf("Should close write handle: %v", err)
	}
	writeHandle = windows.InvalidHandle

	// Test reading
	reader := &windowsHandleReader{handle: readHandle}
	buffer := make([]byte, len(testData))
	n, err := reader.Read(buffer)
	require.NoError(t, err, "Should read from handle")
	assert.Equal(t, len(testData), n, "Should read expected number of bytes")
	assert.Equal(t, testData, buffer, "Should read expected data")
}

func TestWindowsHandleWriter(t *testing.T) {
	// Create a pipe for testing
	var readHandle, writeHandle windows.Handle
	err := windows.CreatePipe(&readHandle, &writeHandle, nil, 0)
	require.NoError(t, err, "Should create pipe for testing")
	defer closeHandles(readHandle, writeHandle)

	// Test writing
	testData := []byte("Hello, Windows Handle Writer!")
	writer := &windowsHandleWriter{handle: writeHandle}
	n, err := writer.Write(testData)
	require.NoError(t, err, "Should write to handle")
	assert.Equal(t, len(testData), n, "Should write expected number of bytes")

	// Close write handle
	if err := windows.CloseHandle(writeHandle); err != nil {
		t.Fatalf("Should close write handle: %v", err)
	}

	// Verify data was written by reading it back
	buffer := make([]byte, len(testData))
	var bytesRead uint32
	err = windows.ReadFile(readHandle, buffer, &bytesRead, nil)
	require.NoError(t, err, "Should read back written data")
	assert.Equal(t, uint32(len(testData)), bytesRead, "Should read back expected number of bytes")
	assert.Equal(t, testData, buffer, "Should read back expected data")
}

// BenchmarkConPtyCreation benchmarks ConPty creation performance
func BenchmarkConPtyCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		inputRead, inputWrite, outputRead, outputWrite, err := createConPtyPipes()
		if err != nil {
			b.Fatal(err)
		}

		hPty, err := createConPty(80, 24, inputRead, outputWrite)
		if err != nil {
			closeHandles(inputRead, inputWrite, outputRead, outputWrite)
			b.Fatal(err)
		}

		// Clean up
		if ret, _, err := procClosePseudoConsole.Call(uintptr(hPty)); ret == 0 {
			log.Debugf("ClosePseudoConsole failed: %v", err)
		}
		closeHandles(inputRead, inputWrite, outputRead, outputWrite)
	}
}
