package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_EqualReturnsTrueForIdenticalLists(t *testing.T) {
	list1 := List{"domain1", "domain2", "domain3"}
	list2 := List{"domain1", "domain2", "domain3"}

	assert.True(t, list1.Equal(list2))
}

func Test_EqualReturnsFalseForDifferentLengths(t *testing.T) {
	list1 := List{"domain1", "domain2"}
	list2 := List{"domain1", "domain2", "domain3"}

	assert.False(t, list1.Equal(list2))
}

func Test_EqualReturnsFalseForDifferentElements(t *testing.T) {
	list1 := List{"domain1", "domain2", "domain3"}
	list2 := List{"domain1", "domain4", "domain3"}

	assert.False(t, list1.Equal(list2))
}

func Test_EqualReturnsTrueForUnsortedIdenticalLists(t *testing.T) {
	list1 := List{"domain3", "domain1", "domain2"}
	list2 := List{"domain1", "domain2", "domain3"}

	assert.True(t, list1.Equal(list2))
}

func Test_EqualReturnsFalseForEmptyAndNonEmptyList(t *testing.T) {
	list1 := List{}
	list2 := List{"domain1"}

	assert.False(t, list1.Equal(list2))
}

func Test_EqualReturnsTrueForBothEmptyLists(t *testing.T) {
	list1 := List{}
	list2 := List{}

	assert.True(t, list1.Equal(list2))
}
