package geolocation

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
	log "github.com/sirupsen/logrus"
)

const mmdbFileName = "GeoLite2-City.mmdb"

type Geolocation struct {
	mmdbPath            string
	mux                 *sync.RWMutex
	sha256sum           []byte
	db                  *maxminddb.Reader
	stopCh              chan struct{}
	reloadCheckInterval time.Duration
}

type Record struct {
	City struct {
		GeonameID uint `maxminddb:"geoname_id"`
		Names     struct {
			En string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"city"`
	Continent struct {
		GeonameID uint   `maxminddb:"geoname_id"`
		Code      string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Country struct {
		GeonameID uint   `maxminddb:"geoname_id"`
		ISOCode   string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func NewGeolocation(datadir string) (*Geolocation, error) {
	mmdbPath := path.Join(datadir, mmdbFileName)

	db, err := openDB(mmdbPath)
	if err != nil {
		return nil, err
	}

	sha256sum, err := getSha256sum(mmdbPath)
	if err != nil {
		return nil, err
	}

	geo := &Geolocation{
		mmdbPath:            mmdbPath,
		mux:                 &sync.RWMutex{},
		sha256sum:           sha256sum,
		db:                  db,
		reloadCheckInterval: 60 * time.Second, // TODO: make configurable
		stopCh:              make(chan struct{}),
	}

	go geo.reloader()

	return geo, nil
}

func openDB(mmdbPath string) (*maxminddb.Reader, error) {
	_, err := os.Stat(mmdbPath)

	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%v does not exist", mmdbPath)
	} else if err != nil {
		return nil, err
	}

	db, err := maxminddb.Open(mmdbPath)
	if err != nil {
		return nil, fmt.Errorf("%v could not be opened: %w", mmdbPath, err)
	}

	return db, nil
}

func getSha256sum(mmdbPath string) ([]byte, error) {
	f, err := os.Open(mmdbPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (gl *Geolocation) Lookup(ip string) (*Record, error) {
	gl.mux.RLock()
	defer gl.mux.RUnlock()

	parsedIp := net.ParseIP(ip)
	if parsedIp == nil {
		return nil, fmt.Errorf("could not parse IP %s", ip)
	}

	var record Record
	err := gl.db.Lookup(parsedIp, &record)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

func (gl *Geolocation) Stop() error {
	close(gl.stopCh)
	if gl.db != nil {
		return gl.db.Close()
	}
	return nil
}

func (gl *Geolocation) reloader() {
	for {
		select {
		case <-gl.stopCh:
			return
		case <-time.After(gl.reloadCheckInterval):
			newSha256sum1, err := getSha256sum(gl.mmdbPath)
			if err != nil {
				log.Errorf("failed to calculate sha256 sum for '%s': %s", gl.mmdbPath, err)
				continue
			}
			if !bytes.Equal(gl.sha256sum, newSha256sum1) {
				// we check sum twice just to avoid possible case when we reload during update of the file
				// considering the frequency of file update (few times a week) checking sum twice should be enough
				time.Sleep(50 * time.Millisecond)
				newSha256sum2, err := getSha256sum(gl.mmdbPath)
				if err != nil {
					log.Errorf("failed to calculate sha256 sum for '%s': %s", gl.mmdbPath, err)
					continue
				}
				if !bytes.Equal(newSha256sum1, newSha256sum2) {
					log.Errorf("sha256 sum changed during reloading of '%s'", gl.mmdbPath)
					continue
				}
				err = gl.reload(newSha256sum2)
				if err != nil {
					log.Errorf("reload failed: %s", err)
				}
			} else {
				log.Debugf("No changes in '%s', no need to reload. Next check is in %.0f seconds.",
					gl.mmdbPath, gl.reloadCheckInterval.Seconds())
			}
		}
	}
}

func (gl *Geolocation) reload(newSha256sum []byte) error {
	gl.mux.Lock()
	defer gl.mux.Unlock()

	log.Infof("Reloading '%s'", gl.mmdbPath)

	err := gl.db.Close()
	if err != nil {
		return err
	}

	db, err := openDB(gl.mmdbPath)
	if err != nil {
		return err
	}

	gl.db = db
	gl.sha256sum = newSha256sum

	log.Infof("Successfully reloaded '%s'", gl.mmdbPath)

	return nil
}
