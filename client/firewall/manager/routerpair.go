package manager

type RouterPair struct {
	ID          string
	Source      string
	Destination string
	Masquerade  bool
}

func GetInPair(pair RouterPair) RouterPair {
	return RouterPair{
		ID: pair.ID,
		// invert Source/Destination
		Source:      pair.Destination,
		Destination: pair.Source,
		Masquerade:  pair.Masquerade,
	}
}
