func (nw *NetworkWatcher) Start(ctx context.Context, callback func()) {
	if nw.cancel != nil {
		log.Warn("Network monitor: already running, stopping previous watcher")
		nw.Stop()
	}
	if ctx.Err() != nil {
		log.Info("Network monitor: not starting, context is already cancelled")
		return
	}

	ctx, nw.cancel = context.WithCancel(ctx)
	defer nw.Stop()

	var nexthop4, nexthop6 netip.Addr
	var intf4, intf6 *net.Interface

	operation := func() error {
		var errv4, errv6 error
		nexthop4, intf4, errv4 = routemanager.GetNextHop(netip.IPv4Unspecified())
		nexthop6, intf6, errv6 = routemanager.GetNextHop(netip.IPv6Unspecified())

		if errv4 != nil && errv6 != nil {
			return errors.New("failed to get default next hops")
		}

		if errv4 == nil {
			log.Debugf("Network monitor: IPv4 default route: %s, interface: %s", nexthop4, intf4.Name)
		}
		if errv6 == nil {
			log.Debugf("Network monitor: IPv6 default route: %s, interface: %s", nexthop6, intf6.Name)
		}

		// continue if either route was found
		return nil
	}