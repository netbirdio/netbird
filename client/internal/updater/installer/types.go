package installer

type Type struct {
	name         string
	downloadable bool
}

func (t Type) String() string {
	return t.name
}

func (t Type) Downloadable() bool {
	return t.downloadable
}
