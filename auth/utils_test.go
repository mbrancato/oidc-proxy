package auth

import (
	"github.com/stretchr/testify/assert"
	"regexp"
	"testing"
)

func TestConvertClaimString(t *testing.T) {
	testString := `{"a": 20, "b": 50.3, "c": "foo", "d": null}`
	res, err := ConvertClaimString(testString)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	claims := *res
	switch claims["a"].(type) {
	case float64:
		assert.True(t, true)
	default:
		assert.True(t, false)
	}
	switch claims["b"].(type) {
	case float64:
		assert.True(t, true)
	default:
		assert.True(t, false)
	}
	switch claims["c"].(type) {
	case *regexp.Regexp:
		assert.True(t, true)
	default:
		assert.True(t, false)
	}
	switch claims["d"].(type) {
	case nil:
		assert.True(t, true)
	default:
		assert.True(t, false)
	}
}
