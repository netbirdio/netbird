//go:build !ios && !android

package debug

import (
	"fmt"
	"strings"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

func (g *BundleGenerator) addRoutes() error {
	detailedRoutes, err := systemops.GetDetailedRoutesFromTable()
	if err != nil {
		return fmt.Errorf("get detailed routes: %w", err)
	}

	routesContent := formatRoutesTable(detailedRoutes, g.anonymize, g.anonymizer)
	routesReader := strings.NewReader(routesContent)
	if err := g.addFileToZip(routesReader, "routes.txt"); err != nil {
		return fmt.Errorf("add routes file to zip: %w", err)
	}

	return nil
}
