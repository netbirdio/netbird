func checkChange(ctx context.Context, nexthopv4 netip.Addr, intfv4 *net.Interface, nexthop6 netip.Addr, intfv6 *net.Interface, callback func()) error {
	if intfv4 == nil && intfv6 == nil {
		return errors.New("no interfaces available")
	}
	
	linkChan := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	defer close(done)

	if err := netlink.LinkSubscribe(linkChan, done); err != nil {
		return fmt.Errorf("subscribe to link updates: %v", err)
	}
