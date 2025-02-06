package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type testObject struct {
	value int
}

func (t testObject) Equal(other testObject) bool {
	return t.value == other.value
}

func Test_MergeUniqueArraysWithoutDuplicates(t *testing.T) {
	arr1 := []testObject{{value: 1}, {value: 2}}
	arr2 := []testObject{{value: 2}, {value: 3}}
	result := MergeUnique(arr1, arr2)
	assert.Len(t, result, 3)
	assert.Contains(t, result, testObject{value: 1})
	assert.Contains(t, result, testObject{value: 2})
	assert.Contains(t, result, testObject{value: 3})
}

func Test_MergeUniqueHandlesEmptyArrays(t *testing.T) {
	arr1 := []testObject{}
	arr2 := []testObject{}
	result := MergeUnique(arr1, arr2)
	assert.Empty(t, result)
}

func Test_MergeUniqueHandlesOneEmptyArray(t *testing.T) {
	arr1 := []testObject{{value: 1}, {value: 2}}
	arr2 := []testObject{}
	result := MergeUnique(arr1, arr2)
	assert.Len(t, result, 2)
	assert.Contains(t, result, testObject{value: 1})
	assert.Contains(t, result, testObject{value: 2})
}
