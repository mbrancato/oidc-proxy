package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

func TestStaticJWTManager(t *testing.T) {
	retConfig := &StaticTokenConfig{
		Token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3Rlc3Qtc3ZjIiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6InRlc3Qtc3ZjIiwiZXhwIjo0NTE2MjM5MDIyLCJpYXQiOjE1MTYyMzkwMjJ9.r04Ap1R7zgjDujllOwGb-SeHyzmDPo_vBcX6tOgJaig`,
	}
	retriever := new(StaticTokenRetriever)
	err := retriever.Configure(retConfig)
	assert.Nil(t, err)

	manager := NewJwtManager(retriever)
	token, err := manager.Token("foo")
	assert.Nil(t, err)
	assert.Equal(t, token, retConfig.Token)
}

func TestManualJWTManager(t *testing.T) {
	retConfig := &ManualTokenConfig{
		Key:           "testing",
		SigningMethod: "hs256",
		Issuer:        "https://foo",
		Subject:       "foo@test",
	}
	retriever := new(ManualTokenRetriever)
	err := retriever.Configure(retConfig)
	assert.Nil(t, err)

	manager := NewJwtManager(retriever)
	tokenString, err := manager.Token("foo")
	assert.Nil(t, err)

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("testing"), nil
	})
	assert.Nil(t, err)
	assert.Equal(t, claims["aud"], "foo")
}
