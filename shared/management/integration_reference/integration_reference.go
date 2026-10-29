package integration_reference

import (
	"fmt"
	"strings"
)

// IntegrationReference holds the reference to a particular integration
type IntegrationReference struct {
	ID              int
	IntegrationType string
}

func (ir IntegrationReference) String() string {
	return fmt.Sprintf("%s:%d", ir.IntegrationType, ir.ID)
}

func (ir IntegrationReference) CacheKey(path ...string) string {
	if len(path) == 0 {
		return ir.String()
	}
	return fmt.Sprintf("%s:%s", ir.String(), strings.Join(path, ":"))
}
