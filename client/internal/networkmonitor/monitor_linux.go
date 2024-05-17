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
	routeChan := make(chan netlink.RouteUpdate)
	if err := netlink.RouteSubscribe(routeChan, done); err != nil {
		return fmt.Errorf("subscribe to route updates: %v", err)
	}

	log.Info("Network monitor: started")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		// handle interface state changes
		case update := <-linkChan:
			if (intfv4 == nil || update.Index != int32(intfv4.Index)) && (intfv6 == nil || update.Index != int32(intfv6.Index)) {
				continue
			}