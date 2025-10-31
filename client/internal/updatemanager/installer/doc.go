// Package installer provides functionality for managing application updates and installations .
// It handles the complete update lifecycle including installation execution,
// process management, and result reporting.
//
// # Architecture
//
// The installer package uses a two-process architecture:
//
//  1. Service Process: The main application process that initiates updates
//  2. Updater Process: A detached process that performs the actual installation
//
// This separation ensures that the application can be updated while running, and allows
// the updater to restart the application after installation completes.
//
// # Update Flow
//
// The typical update flow follows these steps:
//
//  1. Service calls RunInstallation() with an installer file (.exe or .msi)
//  2. Service copies itself to tempDir as "updater.exe"
//  3. Service launches updater.exe as a detached process with installation parameters
//  4. Updater executes the installer (silently for both .exe and .msi)
//  5. Installer will kill the daemon and UI and it will try to restart it
//  6. Updater restarts the daemon and UI after installation
//  7. Updater writes result.json with success/failure status
//  8. Service watches for result.json using Watch() to get installation outcome
//
// # File Locations
//
// Default temporary directory (Windows):
//   - %ProgramData%\Netbird\tmp-install
//
// Files created during installation:
//   - updater.exe: Copy of the service binary used to run installation
//   - result.json: Installation result with success status and error messages
//   - msi.log: Verbose MSI installer log (MSI installations only)
//   - installer.log: General installer operation log
//
// # Cleanup
//
// The CleanUpInstallerFiles() function removes temporary files:
//
//   - Installer binaries (.exe, .msi)
//   - Updater binary copy
//   - Result files
package installer
