package connprofile

import (
	"encoding/json"
	"time"

	log "github.com/sirupsen/logrus"
)

type Report struct {
	NetworkMapUpdate    time.Time
	OfferSent           float64
	OfferReceived       float64
	WireGuardConfigured float64
	WireGuardConnected  float64
}

func report() {
	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case _ = <-ticker.C:
			printJson()
		}
	}
}

func printJson() {
	profiles := Profiler.GetProfiles()
	reports := make(map[string]Report)
	for key, profile := range profiles {
		reports[key] = Report{
			NetworkMapUpdate:    profile.NetworkMapUpdate,
			OfferSent:           profile.OfferSent.Sub(profile.NetworkMapUpdate).Seconds(),
			OfferReceived:       profile.OfferReceived.Sub(profile.OfferSent).Seconds(),
			WireGuardConfigured: profile.WireGuardConfigured.Sub(profile.OfferReceived).Seconds(),
			WireGuardConnected:  profile.WireGuardConnected.Sub(profile.WireGuardConfigured).Seconds(),
		}
	}
	jsonData, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		log.Errorf("failed to marshal profiles: %v", err)
	}

	log.Infof("profiles: %s", jsonData)
}
