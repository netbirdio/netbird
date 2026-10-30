//go:build !windows && !ios && !android

package cmd

import "github.com/kardianos/service"

// removeLeftoverAdapter does nothing: named installations, which own a derived
// adapter, exist only on Windows.
func removeLeftoverAdapter(service.Service) {}
