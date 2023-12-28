package posturechecks

type PostureChecker interface {
	Run() (bool, error)
}

type PostureCheck struct {
	ID        string           `gorm:"primaryKey"`
	AccountID string           `gorm:"index"`
	PolicyID  string           `gorm:"index"`
	Checks    []PostureChecker `gorm:"serializer:json"`
}
