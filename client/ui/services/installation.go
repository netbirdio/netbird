//go:build !android && !ios && !freebsd && !js

package services

import "context"

// InstallationDetails is what the UI shows about the installation it belongs
// to. The default installation has Named false and nothing else set.
type InstallationDetails struct {
	Named bool   `json:"named"`
	Name  string `json:"name"`
	Label string `json:"label"`
	// Color is #RRGGBB, or empty when the installation has no colour.
	Color string `json:"color"`
	Role  string `json:"role"`
}

// Installation exposes the installation details to the frontend, read-only.
type Installation struct {
	details InstallationDetails
}

// NewInstallation returns the service for the given details.
func NewInstallation(details InstallationDetails) *Installation {
	return &Installation{details: details}
}

// Details returns the details of the installation this UI belongs to.
func (i *Installation) Details(_ context.Context) InstallationDetails {
	return i.details
}
