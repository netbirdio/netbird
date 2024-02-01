package geolocation

type Manager struct {
	Store *SqliteStore
}

func Newmanager(store *SqliteStore) *Manager {
	return &Manager{
		Store: store,
	}
}

func (m *Manager) GetAllCountries() ([]string, error) {
	countries, err := m.Store.GetAllCountries()
	if err != nil {
		return nil, err
	}

	var validCountries []string
	for _, country := range countries {
		if country != "" {
			validCountries = append(validCountries, country)
		}
	}
	return validCountries, nil
}

func (m *Manager) GetCitiesByCountry(countryISOCode string) ([]string, error) {
	cities, err := m.Store.GetCitiesByCountry(countryISOCode)
	if err != nil {
		return nil, err
	}
	var validCities []string
	for _, country := range cities {
		if country != "" {
			validCities = append(validCities, country)
		}
	}
	return validCities, nil
}
