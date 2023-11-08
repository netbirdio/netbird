package listener

// EngineReadyListener is a callback interface for mobile system
type EngineReadyListener interface {
	// Notify invoke when engine is ready
	Notify()
}
