func checkChange(ctx context.Context, nexthopv4 netip.Addr, intfv4 *net.Interface, nexthop6 netip.Addr, intfv6 *net.Interface, callback func()) error {
	if intfv4 == nil && intfv6 == nil {
		return errors.New("no interfaces available")
	}