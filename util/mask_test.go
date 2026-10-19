package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaskCredentials(t *testing.T) {
	tests := []struct{ in, want string }{
		{"host=pg user=nb password=s3cret dbname=nb", "host=pg user=nb password=xxxxx dbname=nb"},
		{"host=pg password='my s3cret' dbname=nb", "host=pg password=xxxxx dbname=nb"},
		{"host=pg password = s3cret sslpassword=s3cret", "host=pg password=xxxxx sslpassword=xxxxx"},
		{"postgres://nb:s3cret@pg:5432/nb", "postgres://nb:xxxxx@pg:5432/nb"},
		{"postgres://nb:s3cret@pg/nb?password=other", "postgres://nb:xxxxx@pg/nb?password=xxxxx"},
		{"postgres://pg/nb?password=s3cret&sslmode=require", "postgres://pg/nb?password=xxxxx&sslmode=require"},
		{"nb:s3cret@tcp(mysql:3306)/nb", "nb:xxxxx@tcp(mysql:3306)/nb"},
		{"nb:s3@cret@tcp(mysql:3306)/nb", "nb:xxxxx@tcp(mysql:3306)/nb"},
		{"redis://:s3%40cret@redis:6379", "redis://:xxxxx@redis:6379"},
		{"redis://u:s3,cret@a:6379,redis://u:s3cret@b:6379", "redis://u:xxxxx@a:6379,redis://u:xxxxx@b:6379"},
		{"redis://:s3cret@redis:6379", "redis://:xxxxx@redis:6379"},
		{"redis://s3cret@redis:6379", "redis://xxxxx@redis:6379"},
		{"redis://user:s3cret@a:6379, redis://user:s3cret@b:6379", "redis://user:xxxxx@a:6379,redis://user:xxxxx@b:6379"},
		{"redis://:s3c/ret@redis:6379", "xxxxx"},
		{"redis://redis:6379", "redis://redis:6379"},
		{"http://10.0.0.5:8080/users/alice@corp.com", "http://10.0.0.5:8080/users/alice@corp.com"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, MaskCredentials(tt.in), tt.in)
	}
}

func TestMaskSecret(t *testing.T) {
	assert.Equal(t, "s3cr...", MaskSecret("s3cret"))
	assert.Equal(t, "xxxxx", MaskSecret("abc"))
	assert.Equal(t, "päss...", MaskSecret("pässwort"))
}
