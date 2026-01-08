// Package updatemanager provides automatic update management for the NetBird client.
// It monitors for new versions, handles update triggers from management server directives,
// and orchestrates the download and installation of client updates.
//
// # Overview
//
// The update manager operates as a background service that continuously monitors for
// available updates and automatically initiates the update process when conditions are met.
// It integrates with the installer package to perform the actual installation.
//
// # Update Flow
//
// The complete update process follows these steps:
//
//  1. Manager receives update directive via SetVersion() or detects new version
//  2. Manager validates update should proceed (version comparison, rate limiting)
//  3. Manager publishes "updating" event to status recorder
//  4. Manager persists UpdateState to track update attempt
//  5. Manager downloads installer file (.msi or .exe) to temporary directory
//  6. Manager triggers installation via installer.RunInstallation()
//  7. Installer package handles the actual installation process
//  8. On next startup, CheckUpdateSuccess() verifies update completion
//  9. Manager publishes success/failure event to status recorder
//  10. Manager cleans up UpdateState
//
// # State Management
//
// Update state is persisted across restarts to track update attempts:
//
//   - PreUpdateVersion: Version before update attempt
//   - TargetVersion: Version attempting to update to
//
// This enables verification of successful updates and appropriate user notification
// after the client restarts with the new version.
package updatemanager
