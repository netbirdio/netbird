//go:build ios

package testutil

func CreatePostgresTestContainer() (func(), string, error) {
	return func() {
		// Empty function for Postgres
	}, "", nil
}

func CreateMysqlTestContainer() (func(), string, error) {
	return func() {
		// Empty function for MySQL
	}, "", nil
}

func CreateRedisTestContainer() (func(), string, error) {
	return func() {
		// Empty function for Redis
	}, "", nil
}
