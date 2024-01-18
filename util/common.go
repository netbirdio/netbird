package util

import "os"

// SliceDiff returns the elements in slice `x` that are not in slice `y`
func SliceDiff(x, y []string) []string {
	mapY := make(map[string]struct{}, len(y))
	for _, val := range y {
		mapY[val] = struct{}{}
	}
	var diff []string
	for _, val := range x {
		if _, found := mapY[val]; !found {
			diff = append(diff, val)
		}
	}
	return diff
}

// FileExists returns true if specified file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
