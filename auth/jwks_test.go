package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

type jwksTester struct {
	privateKey *rsa.PrivateKey
	keyId      string
	jwksUrl    string
}

func (t *jwksTester) jwksHandler(w http.ResponseWriter, r *http.Request) {
	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": t.keyId,
		"n":   base64.RawURLEncoding.EncodeToString(t.privateKey.PublicKey.N.Bytes()),
		"e":   base64.URLEncoding.EncodeToString([]byte{1, 0, 1}),
		"use": "sig",
	}

	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}
	_ = json.NewEncoder(w).Encode(jwks)
}

func (t *jwksTester) startJwksServer() *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(t.jwksHandler))
	t.jwksUrl = s.URL
	return s
}

func setupJwksForTest() (*jwksTester, func()) {
	var err error
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	kid := keyFingerprint(key)

	tn := jwksTester{
		privateKey: key,
		keyId:      kid,
	}

	s := tn.startJwksServer()

	closer := func() {
		s.Close()
	}

	return &tn, closer
}

func TestJwksKeyManager(t *testing.T) {
	jwksServer := httptest.NewServer(
		http.HandlerFunc(
			func(rw http.ResponseWriter, r *http.Request) {
				jwksKeys := `
{
  "keys": [
    {
      "kid": "6569c7fdf3374d47840e11fa9760994a",
      "kty": "oct",
      "k": "dGVzdGluZw",
      "use": "sig"
    }
  ]
}`
				_, _ = fmt.Fprintln(rw, jwksKeys)
			},
		),
	)
	claims := &ValidatableMapClaims{}
	claims.AddClaim("aud", "test-svc")
	manager := NewJwksKeyManager(jwksServer.URL, claims)
	validTokenString := `eyJhbGciOiJIUzI1NiIsImtpZCI6IjY1NjljN2ZkZjMzNzRkNDc4NDBlMTFmYTk3NjA5OTRhIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL3Rlc3Qtc3ZjIiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6InRlc3Qtc3ZjIiwiZXhwIjo0NTE2MjM5MDIyLCJpYXQiOjE1MTYyMzkwMjJ9.qODQNk26TSsFKrOsPqexULQh0xik0ZY_rHogvJ2Gqx8`

	v, err := manager.Validate(validTokenString)
	assert.True(t, v)
	assert.NoError(t, err)

	expiredTokenString := `eyJhbGciOiJIUzI1NiIsImtpZCI6IjY1NjljN2ZkZjMzNzRkNDc4NDBlMTFmYTk3NjA5OTRhIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoidGVzdC1zdmMiLCJleHAiOjE1MTYyMzkxMDAsImlhdCI6MTUxNjIzOTAwMH0.INfDsTNrgJ1H67Y6lYMeLWJ-g-YobgnikdOOl-tdK9U`
	v, err = manager.Validate(expiredTokenString)
	assert.False(t, v)
	assert.Error(t, err)
}

func TestJwksValidation(t *testing.T) {
	tn, closer := setupJwksForTest()
	defer closer()

	tests := []struct {
		name     string
		claims   jwt.MapClaims
		hasKeyId bool
		success  bool
	}{
		{
			name: "valid token",
			claims: jwt.MapClaims{
				"aud": "test-svc",
				"iss": "https://test-svc",
				"sub": "1234567890",
				"exp": time.Now().Add(time.Minute).Unix(),
				"iat": time.Now().Unix(),
			},
			success:  true,
			hasKeyId: true,
		},
		{
			name: "expired token",
			claims: jwt.MapClaims{
				"aud": "test-svc",
				"iss": "https://test-svc",
				"sub": "1234567890",
				"exp": time.Now().Add(-time.Minute).Unix(),
				"iat": time.Now().Add(-2 * time.Minute).Unix(),
			},
			success:  false,
			hasKeyId: true,
		},
		{
			name: "valid token missing kid",
			claims: jwt.MapClaims{
				"aud": "test-svc",
				"iss": "https://test-svc",
				"sub": "1234567890",
				"exp": time.Now().Add(time.Minute).Unix(),
				"iat": time.Now().Unix(),
			},
			success:  true,
			hasKeyId: false,
		},
		{
			name: "expired token missing kid",
			claims: jwt.MapClaims{
				"aud": "test-svc",
				"iss": "https://test-svc",
				"sub": "1234567890",
				"exp": time.Now().Add(-time.Minute).Unix(),
				"iat": time.Now().Add(-2 * time.Minute).Unix(),
			},
			success:  false,
			hasKeyId: false,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, tt.claims)
				if tt.hasKeyId {
					token.Header["kid"] = tn.keyId
				}
				tokenString, err := token.SignedString(tn.privateKey)
				assert.NoError(t, err)

				manager := NewJwksKeyManager(tn.jwksUrl, &ValidatableMapClaims{"aud": "test-svc"})
				valid, err := manager.Validate(tokenString)
				if tt.success {
					assert.True(t, valid)
					assert.NoError(t, err)
				} else {
					assert.False(t, valid)
					assert.Error(t, err)
				}
			},
		)
	}
}

func keyFingerprint(key *rsa.PrivateKey) string {
	hash := sha256.Sum256(
		[]byte(key.N.String() + key.D.String() + string(rune(key.E)) + key.Primes[0].String() + key.
			Primes[1].String()),
	)
	hex := fmt.Sprintf("%x", hash)
	return hex
}
