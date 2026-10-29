package networkmapdb

import (
	"database/sql"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNullStringSupport(t *testing.T) {
	src := withNullString{Name: sql.NullString{String: "string", Valid: true}}
	dst := withString{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.Equal(t, withString{Name: "string"}, dst)

	src = withNullString{Name: sql.NullString{Valid: false}}
	dst = withString{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.Equal(t, withString{Name: ""}, dst)
}

func TestNullBoolSupport(t *testing.T) {
	src := withNullBool{TrueOrFalse: sql.NullBool{Bool: true, Valid: true}}
	dst := withBool{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.Equal(t, withBool{TrueOrFalse: true}, dst)

}

func TestRawJsonSupport(t *testing.T) {
	jb, _ := json.Marshal(embeddedS{Name: "blob-name", SomeField: 1})
	src := withRawJson{Blob: json.RawMessage(jb)}
	dst := fromJson{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.Equal(t, fromJson{Blob: embeddedS{Name: "blob-name", SomeField: 1}}, dst)

	src1 := withRawJson{}
	dst1 := fromJson{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src1), reflect.ValueOf(&dst1)))
	assert.Equal(t, fromJson{}, dst1)
}

func TestShouldSkipTag(t *testing.T) {
	src5 := withSkipTag{Field: "shouldskip"}
	dst5 := emptySkipTagTarget{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src5), reflect.ValueOf(&dst5)))
	assert.Equal(t, emptySkipTagTarget{}, dst5)

}

func TestMapToTag(t *testing.T) {
	src6 := withMapToTag{Field: "fieldvalue"}
	dst6 := mapToTagTarget{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src6), reflect.ValueOf(&dst6)))
	assert.Equal(t, mapToTagTarget{AnotherField: "fieldvalue"}, dst6)
}

func TestNullableInt64Support(t *testing.T) {
	src := withInt64{Field: sql.NullInt64{Int64: int64(1), Valid: true}}
	dst := int64Target{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.Equal(t, int64Target{Field: 1}, dst)
}

func TestNullableTimeSupport(t *testing.T) {
	now := time.Now()
	src := withNullableTime{Field: sql.NullTime{Time: now, Valid: true}}
	dst := nullableTimeTarget{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.Equal(t, nullableTimeTarget{Field: now}, dst)
}

func TestNullableTimePointerSupport(t *testing.T) {
	now := time.Now()
	src := withNullableTime{Field: sql.NullTime{Time: now, Valid: true}}
	dst := nullableTimePointerTarget{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.Equal(t, nullableTimePointerTarget{Field: &now}, dst)
}

func TestStringSLiceSupport(t *testing.T) {
	src := withStringSlice{Field: []string{"one"}}
	dst := withStringSlice{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.Equal(t, withStringSlice{Field: []string{"one"}}, dst)
}

func TestNullStringSLiceSupport(t *testing.T) {
	src := withStringSlice{}
	dst := withStringSlice{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.Equal(t, withStringSlice{}, dst)
}

func TestWithMultipleFields(t *testing.T) {
	now := time.Now()
	src := withMultipleFields{
		Field1: sql.NullString{String: "aaa", Valid: true},
		Field2: sql.NullBool{Bool: true, Valid: true},
		Field3: sql.NullTime{Time: now, Valid: true},
		Field4: sql.NullInt64{Int64: 1, Valid: true},
		Field5: "another",
	}
	dst := multipleFieldsTarget{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.Equal(t, multipleFieldsTarget{
		Field1: "aaa",
		Field2: true,
		Field3: now,
		Field4: 1,
		Field5: "another",
	}, dst)
}

func TestEmptyPublicIdsFilled(t *testing.T) {
	src := withEmptyPublicIds{}
	dst := emptyPublicIdTarget{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.NotEmpty(t, dst.PublicID)
	assert.NotEmpty(t, dst.PublicId)
}

// only []byte and []uint8 slices with "json" tag are being parsed
func TestByteSliceSupport(t *testing.T) {
	src := withByteSlice{
		Field: []byte("[\"one\",\"two\",\"three\"]"),
	}
	dst := byteSliceTarget{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.Equal(t, []string{"one", "two", "three"}, dst.Field)
}

func TestUint8SliceSupport(t *testing.T) {
	src := withUint8Slice{
		Field: []uint8("[\"one\",\"two\",\"three\"]"),
	}
	dst := uint8SliceTarget{}
	assert.NoError(t, FromSqlTypesToSharedTypes(reflect.ValueOf(&src), reflect.ValueOf(&dst)))
	assert.Equal(t, []string{"one", "two", "three"}, dst.Field)
}

type withNullString struct {
	Name sql.NullString
}

type withString struct {
	Name string
}

type withMultipleFields struct {
	Field1 sql.NullString
	Field2 sql.NullBool
	Field3 sql.NullTime
	Field4 sql.NullInt64
	Field5 string
}

type multipleFieldsTarget struct {
	Field1 string
	Field2 bool
	Field3 time.Time
	Field4 int64
	Field5 string
}

type withNullBool struct {
	TrueOrFalse sql.NullBool
}

type withBool struct {
	TrueOrFalse bool
}

type withRawJson struct {
	Blob json.RawMessage
}

type embeddedS struct {
	Name      string
	SomeField int
}
type fromJson struct {
	Blob embeddedS
}

type withSkipTag struct {
	Field string `nmap:"skip"`
}

type emptySkipTagTarget struct {
	Field string
}

type withMapToTag struct {
	Field string `nmap:"map_to:AnotherField"`
}

type mapToTagTarget struct {
	AnotherField string
}

type withInt64 struct {
	Field sql.NullInt64
}

type int64Target struct {
	Field int
}

type withNullableTime struct {
	Field sql.NullTime
}

type nullableTimeTarget struct {
	Field time.Time
}

type nullableTimePointerTarget struct {
	Field *time.Time
}

type withStringSlice struct {
	Field []string
}

type withEmptyPublicIds struct {
	PublicID sql.NullString
	PublicId sql.NullString
}

type emptyPublicIdTarget struct {
	PublicID string
	PublicId string
}

type withByteSlice struct {
	Field []byte `nmap:"json"`
}

type byteSliceTarget struct {
	Field []string
}

type withUint8Slice struct {
	Field []byte `nmap:"json"`
}

type uint8SliceTarget struct {
	Field []string
}
