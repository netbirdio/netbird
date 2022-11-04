package server

import (
	"fmt"
	nbdns "github.com/netbirdio/netbird/dns"
	"strconv"
)

func getPeerHostLabel(name string, peerLabels map[string]struct{}) (string, error) {
	label, err := nbdns.GetParsedDomainLabel(name)
	if err != nil {
		return "", err
	}

	uniqueLabel := getUniqueHostLabel(label, peerLabels)
	if uniqueLabel == "" {
		return "", fmt.Errorf("couldn't find a unique valid lavel for %s, parsed label %s", name, label)
	}
	return uniqueLabel, nil
}

// getUniqueHostLabel look for a unique host label, and if doesn't find add a suffix up to 999
func getUniqueHostLabel(name string, peerLabels map[string]struct{}) string {
	_, found := peerLabels[name]
	if !found {
		return name
	}
	for i := 1; i < 1000; i += 1 {
		nameWithSuffix := name + "-" + strconv.Itoa(i)
		_, found = peerLabels[nameWithSuffix]
		if !found {
			return nameWithSuffix
		}
	}
	return ""
}
