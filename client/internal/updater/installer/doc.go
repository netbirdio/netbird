// Package installer provides functionality for managing NetBird application
// updates and installations across Windows, macOS. It handles
// the complete update lifecycle including artifact download, cryptographic verification,
// installation execution, process management, and result reporting.
//
// # Architecture
//
// The installer package uses a two-process architecture to enable self-updates:
//
//  1. Service Process: The main NetBird daemon process that initiates updates
//  2. Updater Process: A detached child process that performs the actual installation
//
// This separation is critical because:
//   - The service binary cannot update itself while running
//   - The installer (EXE/MSI/PKG) will terminate the service during installation
//   - The updater process survives service termination and restarts it after installation
//   - Results can be communicated back to the service after it restarts
//
// # Update Flow
//
// Service Process (RunInstallation):
//
//  1. Validates target version format (semver)
//  2. Determines installer type (EXE, MSI, PKG, or Homebrew)
//  3. Downloads installer file from GitHub releases (if applicable)
//  4. Verifies installer signature using reposign package (cryptographic verification in service process before
//     launching updater)
//  5. Copies service binary to tempDir as "updater" (or "updater.exe" on Windows)
//  6. Launches updater process with detached mode:
//     - --temp-dir: Temporary directory path
//     - --service-dir: Service installation directory
//     - --installer-file: Path to downloaded installer (if applicable)
//     - --dry-run: Optional flag to test without actually installing
//  7. Service process continues running (will be terminated by installer later)
//  8. Service can watch for result.json using ResultHandler.Watch() to detect completion
//
// Updater Process (Setup):
//
//  1. Receives parameters from service via command-line arguments
//  2. Runs installer with appropriate silent/quiet flags:
//     - Windows EXE: installer.exe /S
//     - Windows MSI: msiexec.exe /i installer.msi /quiet /qn /l*v msi.log
//     - macOS PKG: installer -pkg installer.pkg -target /
//     - macOS Homebrew: brew upgrade netbirdio/tap/netbird
//  3. Installer terminates daemon and UI processes
//  4. Installer replaces binaries with new version
//  5. Updater waits for installer to complete
//  6. Updater restarts daemon:
//     - Windows: netbird.exe service start
//     - macOS/Linux: netbird service start
//  7. Updater restarts UI:
//     - Windows: Launches netbird-ui.exe as active console user using CreateProcessAsUser
//     - macOS: Uses launchctl asuser to launch NetBird.app for console user
//     - Linux: Not implemented (UI typically auto-starts)
//  8. Updater writes result.json with success/error status
//  9. Updater process exits
//
// # Result Communication
//
// The ResultHandler (result.go) manages communication between updater and service:
//
// Result Structure:
//
//	type Result struct {
//	    Success    bool      // true if installation succeeded
//	    Error      string    // error message if Success is false
//	    ExecutedAt time.Time // when installation completed
//	}
//
// Result files are automatically cleaned up after being read.
//
// # File Locations
//
// Temporary Directory (platform-specific):
//
// Windows:
//   - Path: %ProgramData%\Netbird\tmp-install
//   - Example: C:\ProgramData\Netbird\tmp-install
//
// macOS:
//   - Path: /var/lib/netbird/tmp-install
//   - Requires root permissions
//
// Files created during installation:
//
//		tmp-install/
//	   installer.log
//		  updater[.exe]                    # Copy of service binary
//		  netbird_installer_*.[exe|msi|pkg] # Downloaded installer
//		  result.json                       # Installation result
//		  msi.log                           # MSI verbose log (Windows MSI only)
//
// # API Reference
//
// # Cleanup
//
// CleanUpInstallerFiles() removes temporary files after successful installation:
//   - Downloaded installer files (*.exe, *.msi, *.pkg)
//   - Updater binary copy
//   - Does NOT remove result.json (cleaned by ResultHandler after read)
//   - Does NOT remove msi.log (kept for debugging)
//
// # Dry-Run Mode
//
// Dry-run mode allows testing the update process without actually installing:
//
// Enable via environment variable:
//
//	export NB_AUTO_UPDATE_DRY_RUN=true
//	netbird service install-update 0.29.0
package installer
