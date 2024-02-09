package detect_cloud

import (
	"os"
	"strings"
)

func detectContainer() string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}

	fc := string(b)
	kube := strings.Contains(fc, "kube")
	container := strings.Contains(fc, "containerd")

	if kube {
		return "K8S Container"
	}

	if container {
		return "Container"
	}

	return ""
}
