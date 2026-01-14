package reverseproxy

// RequestDataCallback is called for each request that passes through the proxy
type RequestDataCallback func(data RequestData)

// RequestData contains metadata about a proxied request
type RequestData struct {
	ServiceID    string
	Host         string
	Path         string
	DurationMs   int64
	Method       string
	ResponseCode int32
	SourceIP     string

	AuthMechanism string
	UserID        string
	AuthSuccess   bool
}
