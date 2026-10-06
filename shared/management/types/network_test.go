package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type mergeTestObject struct {
	value int
}

func (t mergeTestObject) Equal(other mergeTestObject) bool {
	return t.value == other.value
}

func Test_MergeUniqueArraysWithoutDuplicates(t *testing.T) {
	arr1 := []mergeTestObject{{value: 1}, {value: 2}}
	arr2 := []mergeTestObject{{value: 2}, {value: 3}}
	result := mergeUnique(arr1, arr2)
	assert.Len(t, result, 3)
	assert.Contains(t, result, mergeTestObject{value: 1})
	assert.Contains(t, result, mergeTestObject{value: 2})
	assert.Contains(t, result, mergeTestObject{value: 3})
}

func Test_MergeUniqueHandlesEmptyArrays(t *testing.T) {
	arr1 := []mergeTestObject{}
	arr2 := []mergeTestObject{}
	result := mergeUnique(arr1, arr2)
	assert.Empty(t, result)
}

func Test_MergeUniqueHandlesOneEmptyArray(t *testing.T) {
	arr1 := []mergeTestObject{{value: 1}, {value: 2}}
	arr2 := []mergeTestObject{}
	result := mergeUnique(arr1, arr2)
	assert.Len(t, result, 2)
	assert.Contains(t, result, mergeTestObject{value: 1})
	assert.Contains(t, result, mergeTestObject{value: 2})
}
