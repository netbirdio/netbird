package peer

func shortenKey(pubKey string) string {
	if len(pubKey) < 7 {
		return pubKey
	}
	return pubKey[:7]
}
