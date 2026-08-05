package nmdata

import "slices"

// GroupAllName is the reserved name of the default group that contains every
// peer in an account.
const GroupAllName = "All"

// Group is the slim twin of types.Group.
type Group struct {
	ID        string
	Name      string
	PublicID  string
	Peers     []string
	Resources []Resource
}

func (g *Group) IsGroupAll() bool {
	return g.Name == GroupAllName
}

func (g *Group) Copy() *Group {
	return &Group{
		ID:        g.ID,
		Name:      g.Name,
		PublicID:  g.PublicID,
		Peers:     slices.Clone(g.Peers),
		Resources: slices.Clone(g.Resources),
	}
}
