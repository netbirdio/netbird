package detect_platform

import (
	"context"
	"os"
)

func detectContainer(ctx context.Context) string {
	if _, exists := os.LookupEnv("KUBERNETES_SERVICE_HOST"); exists {
		return "Kubernetes"
	}

	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "Docker"
	}
	return ""
}
