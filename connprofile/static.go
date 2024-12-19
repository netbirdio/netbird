package connprofile

var (
	Profiler *ConnProfiler
)

func init() {
	Profiler = NewConnProfiler()
	go report()
}
