package auth

import (
	"log"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

// A JwksKeyManager implements the KeyManager interface and supports an
// auto-refreshed JWKS URL for retrieving keys for JWT validation.
type JwksKeyManager struct {
	url            string
	jwks           *keyfunc.JWKS
	expectedClaims *ValidatableMapClaims
}

// Validate will parse and validate a JWT token and its claims.
func (m *JwksKeyManager) Validate(tok string) (bool, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(
		tok, &claims, m.jwks.Keyfunc,
	)
	if err != nil {
		return false, err
	}

	return m.expectedClaims.ValidateClaims(&claims)
}

// NewJwksKeyManager returns a new JwksKeyManager for the specified JWKS URL.
func NewJwksKeyManager(url string, claims *ValidatableMapClaims) *JwksKeyManager {
	m := JwksKeyManager{
		url:            url,
		expectedClaims: claims,
	}

	jwks, err := keyfunc.Get(url, keyfunc.Options{
		RefreshInterval:   10 * time.Minute,
		RefreshUnknownKID: true,
	})
	if err != nil {
		log.Fatalf("failed to get JWKS URL: %v\n", err.Error())
	}
	m.jwks = jwks

	return &m
}
