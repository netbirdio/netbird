package detect_cloud

import (
	"net/http"
)

func detectGCE() string {
	r, err := http.NewRequest("GET", "http://metadata.google.internal", nil)
	if err != nil {
		return ""
	}
	r.Header.Add("Metadata-Flavor", "Google")

	resp, err := hc.Do(r)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "Google Compute Engine"
	}
	return ""
}
