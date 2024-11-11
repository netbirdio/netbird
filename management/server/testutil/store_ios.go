//go:build ios
// +build ios

package testutil

func CreatePostgresTestContainer() (func(), error) { return func() {}, nil }

func CreateMysqlTestContainer() (func(), error) { return func() {}, nil }
