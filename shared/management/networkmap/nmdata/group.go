package nmdata

import "slices"

const groupAllName = "All"

// Group is the slim twin of types.Group.
type Group struct {
	ID        string
	Name      string
	PublicID  string
	Peers     []string
	Resources []Resource
}

func (g *Group) IsGroupAll() bool {
	return g.Name == groupAllName
}

func (g *Group) Copy() *Group {
	return &Group{
		ID:       g.ID,
		Name:     g.Name,
		PublicID: g.PublicID,
		Peers:    slices.Clone(g.Peers),
	}
}
