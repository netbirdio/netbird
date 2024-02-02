package geolocation

type City struct {
	GeoNameID int `gorm:"column:geoname_id"`
	CityName  string
}

type Manager struct {
	Store *SqliteStore
}

// NewManager creates a new Manager instance with the given SqliteStore.
func NewManager(store *SqliteStore) *Manager {
	if store == nil {
		return nil
	}
	return &Manager{
		Store: store,
	}
}

// GetAllCountries retrieves a list of all countries.
func (m *Manager) GetAllCountries() ([]string, error) {
	allCountries, err := m.Store.GetAllCountries()
	if err != nil {
		return nil, err
	}

	countries := make([]string, 0)
	for _, country := range allCountries {
		if country != "" {
			countries = append(countries, country)
		}
	}
	return countries, nil
}

// GetCitiesByCountry retrieves a list of cities in a specific country based on the country's ISO code.
func (m *Manager) GetCitiesByCountry(countryISOCode string) ([]City, error) {
	return m.Store.GetCitiesByCountry(countryISOCode)
}
