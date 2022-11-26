package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJWKSKeyManager(t *testing.T) {
	jwksServer := httptest.NewServer(http.HandlerFunc(
		func(rw http.ResponseWriter, r *http.Request) {
			jwksKeys := `
{
 "keys": [
   {
     "kid": "6569c7fdf3374d47840e11fa9760994a",
     "kty": "oct",
     "k": "dGVzdGluZw=="
   }
 ]
}`
			_, _ = fmt.Fprintln(rw, jwksKeys)
		}),
	)
	claims := &ValidatableMapClaims{}
	claims.AddClaim("aud", "test-svc")
	manager := NewJwksKeyManager(jwksServer.URL, claims)
	validTokenString := `eyJhbGciOiJIUzI1NiIsImtpZCI6IjY1NjljN2ZkZjMzNzRkNDc4NDBlMTFmYTk3NjA5OTRhIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL3Rlc3Qtc3ZjIiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6InRlc3Qtc3ZjIiwiZXhwIjo0NTE2MjM5MDIyLCJpYXQiOjE1MTYyMzkwMjJ9.qODQNk26TSsFKrOsPqexULQh0xik0ZY_rHogvJ2Gqx8`

	v, err := manager.Validate(validTokenString)
	assert.True(t, v)
	assert.Nil(t, err)

	expiredTokenString := `eyJhbGciOiJIUzI1NiIsImtpZCI6IjY1NjljN2ZkZjMzNzRkNDc4NDBlMTFmYTk3NjA5OTRhIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoidGVzdC1zdmMiLCJleHAiOjE1MTYyMzkxMDAsImlhdCI6MTUxNjIzOTAwMH0.INfDsTNrgJ1H67Y6lYMeLWJ-g-YobgnikdOOl-tdK9U`
	v, err = manager.Validate(expiredTokenString)
	assert.False(t, v)
	assert.NotNil(t, err)
}
