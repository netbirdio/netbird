//go:build ios
// +build ios

package testutil

func CreatePostgresTestContainer() (func(), error) {
	return func() {
		// Empty function for Postgres
	}, nil
}

func CreateMysqlTestContainer() (func(), error) {
	return func() {
		// Empty function for MySQL
	}, nil
}
