package nmdata

import "slices"

const groupAllName = "All"

// Group is the slim twin of types.Group.
type Group struct {
	Name     string
	PublicID string
	Peers    []string
}

func (g *Group) IsGroupAll() bool {
	return g.Name == groupAllName
}

func (g *Group) Copy() *Group {
	return &Group{
		Name:     g.Name,
		PublicID: g.PublicID,
		Peers:    slices.Clone(g.Peers),
	}
}
