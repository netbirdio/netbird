package geolocation

type Manager struct {
	Store *SqliteStore
}

func NewManager(store *SqliteStore) *Manager {
	if store == nil {
		return nil
	}
	return &Manager{
		Store: store,
	}
}

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

func (m *Manager) GetCitiesByCountry(countryISOCode string) ([]string, error) {
	allCities, err := m.Store.GetCitiesByCountry(countryISOCode)
	if err != nil {
		return nil, err
	}

	cities := make([]string, 0)
	for _, city := range allCities {
		if city != "" {
			cities = append(cities, city)
		}
	}
	return cities, nil
}
