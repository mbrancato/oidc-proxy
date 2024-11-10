package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStaticKeyManager(t *testing.T) {
	tokenString := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3Rlc3Qtc3ZjIiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6InRlc3Qtc3ZjIiwiZXhwIjo0NTE2MjM5MDIyLCJpYXQiOjE1MTYyMzkwMjJ9.r04Ap1R7zgjDujllOwGb-SeHyzmDPo_vBcX6tOgJaig`

	claims := &ValidatableMapClaims{}
	claims.AddClaim("aud", "test-svc")
	manager := NewStaticKeyManager(tokenString, claims)
	v, err := manager.Validate("test-test")
	assert.False(t, v)
	assert.NotNil(t, err)

	v, err = manager.Validate(tokenString)
	assert.True(t, v)
	assert.Nil(t, err)
}
