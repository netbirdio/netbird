package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMysqlDSN(t *testing.T) {
	assert.Equal(t, "user:pw@tcp(host:3306)/db?charset=utf8&parseTime=True&loc=Local", MysqlDSN("user:pw@tcp(host:3306)/db"))
	assert.Equal(t, "user:pw@tcp(host:3306)/db?tls=true&charset=utf8&parseTime=True&loc=Local", MysqlDSN("user:pw@tcp(host:3306)/db?tls=true"))
}
