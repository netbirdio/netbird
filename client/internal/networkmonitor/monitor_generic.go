func (nw *NetworkWatcher) Start(ctx context.Context, callback func()) {
	if nw.cancel != nil {
		log.Warn("Network monitor: already running, stopping previous watcher")
		nw.Stop()
	}