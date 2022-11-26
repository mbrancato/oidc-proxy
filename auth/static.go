package auth

import (
	"errors"
	"fmt"
	"log"

	"github.com/golang-jwt/jwt/v4"
)

// A StaticTokenRetriever implements the JwtTokenRetriever interface for use with tokens
// that are provided by the user and never updated.
type StaticTokenRetriever struct {
	token string
}

// A StaticTokenConfig contains configuration data used to initialize and
// validate a StaticTokenRetriever object.
type StaticTokenConfig struct {
	Token string `long:"token" env:"TOKEN" description:"Static authentication identity token"`
}

// A StaticKeyManager implements the KeyManager interface and supports a
// static JWT for validation.
type StaticKeyManager struct {
	token          interface{}
	expectedClaims *ValidatableMapClaims
}

// GetToken returns the configured static token.
func (r *StaticTokenRetriever) GetToken(_ string) (string, error) {
	return r.token, nil
}

// Configure will take a valid StaticTokenConfig and use it to configure the token retriever.
func (r *StaticTokenRetriever) Configure(config interface{}) error {
	c, ok := config.(*StaticTokenConfig)
	if !ok {
		log.Fatalln("internal error: incorrect Token config")
	}

	if c.Token == "" {
		return errors.New("static JWT Token must not be empty")
	}
	r.token = c.Token
	return nil
}

// Validate will parse and validate a JWT token and its claims.
func (m *StaticKeyManager) Validate(tok string) (bool, error) {
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(tok, claims)
	if err != nil {
		return false, fmt.Errorf("error parsing token: %w", err)
	}
	if tok == m.token {
		return m.expectedClaims.ValidateClaims(&claims)
	}
	return false, errors.New("static token did not match")
}

// NewStaticKeyManager returns a new StaticKeyManager for the static token
// provided.
func NewStaticKeyManager(token interface{}, claims *ValidatableMapClaims) *StaticKeyManager {
	m := StaticKeyManager{
		token:          token,
		expectedClaims: claims,
	}

	return &m
}
