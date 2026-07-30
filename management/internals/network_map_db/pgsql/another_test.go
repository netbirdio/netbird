package networkmap_pgsql

import (
	"database/sql"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/stretchr/testify/assert"
)

type g1 struct {
	Name sql.NullString
}

type g2 struct {
	Name string
}

type g11 struct {
	Name     sql.NullString
	PublicId sql.NullString
}

type g22 struct {
	Name     string
	PublicId string
}

type g111 struct {
	Name        sql.NullString
	TrueOrFalse sql.NullBool
}

type g222 struct {
	Name        string
	TrueOrFalse bool
}

type g1111 struct {
	Time sql.NullTime
}

type g2222 struct {
	Time time.Time
}

type g11111 struct {
	Blob json.RawMessage
}

type embeddedS struct {
	Name      string
	SomeField int
}
type g22222 struct {
	Blob embeddedS
}

type t1 struct {
	Field string `nmap:"skip"`
}

type dt1 struct {
	Field string
}

type o1 struct {
	Field string `nmap:"map_to:AnotherField"`
}

type do1 struct {
	AnotherField string
}

type ptr1 struct {
	Field sql.NullString
}

type ptro1 struct {
	Field *string
}

type i1 struct {
	Field sql.NullInt64
}

type io1 struct {
	Field int
}

func TestOne(t *testing.T) {

	src := g1{Name: sql.NullString{String: "string", Valid: true}}
	dst := g2{}
	assert.NoError(t, networkmapdb.FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.Equal(t, g2{Name: "string"}, dst)

	src = g1{Name: sql.NullString{Valid: false}}
	dst = g2{}
	assert.NoError(t, networkmapdb.FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.Equal(t, g2{Name: ""}, dst)

	src1 := g11{Name: sql.NullString{String: "aaa", Valid: true}, PublicId: sql.NullString{String: "id", Valid: true}}
	dst1 := g22{}
	assert.NoError(t, networkmapdb.FromSqlTypesToSharedTypes(reflect.ValueOf(&src1), reflect.ValueOf(&dst1)))
	assert.Equal(t, g22{Name: "aaa", PublicId: "id"}, dst1)

	src2 := g111{Name: sql.NullString{String: "aaa", Valid: true}, TrueOrFalse: sql.NullBool{Bool: true, Valid: true}}
	dst2 := g222{}
	assert.NoError(t, networkmapdb.FromSqlTypesToSharedTypes(reflect.ValueOf(&src2), reflect.ValueOf(&dst2)))
	assert.Equal(t, g222{Name: "aaa", TrueOrFalse: true}, dst2)

	jb, _ := json.Marshal(embeddedS{Name: "blob-name", SomeField: 1})
	src3 := g11111{Blob: json.RawMessage(jb)}
	dst3 := g22222{}
	assert.NoError(t, networkmapdb.FromSqlTypesToSharedTypes(reflect.ValueOf(&src3), reflect.ValueOf(&dst3)))
	assert.Equal(t, g22222{Blob: embeddedS{Name: "blob-name", SomeField: 1}}, dst3)

	src4 := g11111{}
	dst4 := g22222{}
	assert.NoError(t, networkmapdb.FromSqlTypesToSharedTypes(reflect.ValueOf(&src4), reflect.ValueOf(&dst4)))
	assert.Equal(t, g22222{}, dst4)

	src5 := t1{Field: "shouldskip"}
	dst5 := dt1{}
	assert.NoError(t, networkmapdb.FromSqlTypesToSharedTypes(reflect.ValueOf(&src5), reflect.ValueOf(&dst5)))
	assert.Equal(t, dt1{}, dst5)

	src6 := o1{Field: "fieldvalue"}
	dst6 := do1{}
	assert.NoError(t, networkmapdb.FromSqlTypesToSharedTypes(reflect.ValueOf(&src6), reflect.ValueOf(&dst6)))
	assert.Equal(t, do1{AnotherField: "fieldvalue"}, dst6)

	src7 := i1{Field: sql.NullInt64{Int64: int64(1), Valid: true}}
	dst7 := io1{Field: 1}
	assert.NoError(t, networkmapdb.FromSqlTypesToSharedTypes(reflect.ValueOf(&src7), reflect.ValueOf(&dst7)))
	assert.Equal(t, io1{Field: 1}, dst7)
}
