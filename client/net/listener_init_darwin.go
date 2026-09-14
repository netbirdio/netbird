package net

func (l *ListenerConfig) init() {
	l.ListenConfig.Control = applyBoundIfToSocket
}
