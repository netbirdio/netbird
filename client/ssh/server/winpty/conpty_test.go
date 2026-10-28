//go:build windows

package winpty

import (
	"io"
	"os"
	"strconv"
	"testing"
	"unsafe"

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

const (
	conPtyHelperHandleEnv = "NB_CONPTY_TEST_INHERITED_HANDLE"
	// exit codes of the helper process started by TestCreateConPtyProcess_NoHandleInheritance.
	// conPtyHelperExitSkipped is distinct from conPtyHelperExitNotInherited so the parent can
	// tell "probed and not inherited" apart from "never probed" (for example if the env var
	// carrying the handle value failed to reach the child); either outcome exits 0 as a bare
	// go test binary, so the exit code alone must disambiguate them.
	conPtyHelperExitNotInherited = 0
	conPtyHelperExitSkipped      = 2
	conPtyHelperExitInherited    = 3
)

// TestCreateConPtyProcess_NoHandleInheritance verifies that a ConPty child does not inherit
// inheritable handles of this process. The daemon holds os/exec pipes (created inheritable by
// os.Pipe) for other users' SSH and SFTP sessions; a shell started with bInheritHandles=TRUE and
// no PROC_THREAD_ATTRIBUTE_HANDLE_LIST would receive all of them.
func TestCreateConPtyProcess_NoHandleInheritance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping process tests in short mode")
	}

	// os.Pipe marks both handles inheritable on Windows, like the pipes os/exec creates
	pipeRead, pipeWrite, err := os.Pipe()
	require.NoError(t, err, "Should create pipe")
	defer func() {
		_ = pipeRead.Close()
		_ = pipeWrite.Close()
	}()

	inputRead, inputWrite, outputRead, outputWrite, err := createConPtyPipes()
	require.NoError(t, err, "Should create ConPty pipes successfully")

	hPty, err := createConPty(80, 24, inputRead, outputWrite)
	require.NoError(t, err, "Should create ConPty successfully")

	siEx, err := setupConPtyStartupInfo(hPty)
	require.NoError(t, err, "Should set up startup info")
	defer func() {
		_, _, _ = procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(siEx.ProcThreadAttributeList)))
	}()

	// The child is this test binary running only the helper below; with no environment
	// passed it inherits ours, including the handle value to probe.
	executable, err := os.Executable()
	require.NoError(t, err, "Should find test binary")
	t.Setenv(conPtyHelperHandleEnv, strconv.FormatUint(uint64(pipeWrite.Fd()), 10))
	commandLine := buildCommandLine([]string{executable, "-test.run=^TestConPtyHandleInheritanceHelper$"})

	pi, err := createConPtyProcess(commandLine, windows.InvalidHandle, nil, "", siEx)
	require.NoError(t, err, "Should create ConPty process")
	defer closeProcessInfo(pi)

	closeHandles(inputRead, outputWrite)

	// Drain the pseudo console output so the child and conhost never block on a full pipe.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = io.Copy(io.Discard, &windowsHandleReader{handle: outputRead})
	}()

	event, err := windows.WaitForSingleObject(pi.Process, 30000)
	require.NoError(t, err, "Should wait for ConPty process")
	if event != windows.WAIT_OBJECT_0 {
		_ = windows.TerminateProcess(pi.Process, 1)
		// Wait for the termination to actually land before reading the exit code or
		// closing handles, or the process can briefly survive as a leaked child.
		_, _ = windows.WaitForSingleObject(pi.Process, 5000)
	}

	var exitCode uint32
	require.NoError(t, windows.GetExitCodeProcess(pi.Process, &exitCode), "Should get exit code")

	if ret, _, err := procClosePseudoConsole.Call(uintptr(hPty)); ret == 0 {
		t.Logf("ClosePseudoConsole failed: %v", err)
	}
	closeHandles(inputWrite)
	<-drained
	closeHandles(outputRead)

	require.NotEqual(t, uint32(conPtyHelperExitSkipped), exitCode, "helper must probe the handle, not skip: the env var should have reached the child")
	require.NotEqual(t, uint32(conPtyHelperExitInherited), exitCode, "ConPty child must not inherit the daemon's pipe handles")
	require.Equal(t, uint32(conPtyHelperExitNotInherited), exitCode, "helper process should run to completion")
}

// TestConPtyHandleInheritanceHelper is the child of TestCreateConPtyProcess_NoHandleInheritance.
// It exits with conPtyHelperExitInherited when the handle value named in the environment is a
// live pipe handle in this process, and with conPtyHelperExitSkipped when run on its own (no
// handle value to probe), which the parent treats as a failure rather than a silent pass.
func TestConPtyHandleInheritanceHelper(t *testing.T) {
	value := os.Getenv(conPtyHelperHandleEnv)
	if value == "" {
		os.Exit(conPtyHelperExitSkipped)
	}

	handleValue, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		os.Exit(4)
	}

	// GetFileType fails when the value is not a handle of this process. A handle value may also
	// be reused for something else, so only a pipe counts as the parent's pipe.
	fileType, err := windows.GetFileType(windows.Handle(handleValue))
	if err == nil && fileType == windows.FILE_TYPE_PIPE {
		os.Exit(conPtyHelperExitInherited)
	}
	os.Exit(conPtyHelperExitNotInherited)
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
