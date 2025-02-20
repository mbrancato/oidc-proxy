package auth

import (
	"encoding/base64"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`

const publicKey = `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwMJ9pLEXsvaM/YXPV24h
OpXzmBnuF6We9b9ua2DMUVSWvTV1AckpzDaKq0W+ZZMdSau4PF72MzScWjNYeR7I
yV/ZGxjANtsSOk1hhyDTD9A2l3sd48T2QxtCnLeQTByBvjJsQWbHzR7wKP9REPx2
XsAWs/kYHwhce5y+ybkYl/3xi2vpijfm1R9saxaJuJvNeB8wpTJCDofyyJpL8KKt
Lsa1P8ZJ05GSbK+B5/RTFvbArHt8R1gSD3nCsAEaKn9cTrCLXaQzcs74TQ6qs14k
LvL7gCy89e8XlO3hMousGy4VfFTriPWjc222gPYRaLX5Br4+kGH/Q1wy58b3DRlT
PeLel84CPoLTDxS9YUQOFxaJIYyvbsbkzo4EebL+9B9MpEbZLc0WmGawbz4lodoo
PPCsQndUdY3w9xGD253CTHS98BJ/9QXKK6qhqMA6cavHo0UV3wTcV8LU2NbCGA8J
Md8RJOdm/U+TnMyF2VS283laycXLdrmOJdg3NYy0xvvKdU1dXp5SHA6pURlCh0R4
54i+xHMH3NgkID1Xn7lSyejRlHAa4QWJjXUk8PI5YOzTN+cAxV9IKvnWAs9wi8be
NeVa/KG8YnyCQ53Veohs5uqCDufeSy+m7RA7mgKmAYc8Tnmd9iWjW2Lem2G25vou
vc4/3racNzs2x9SjrnYoCscCAwEAAQ==
-----END PUBLIC KEY-----
`

func TestManualTokenRetriever_RSA(t *testing.T) {
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
	if err != nil {
		return
	}

	retConfig := &ManualTokenConfig{
		Key:           privateKey,
		SigningMethod: "RS256",
		Issuer:        "https://foo",
		Subject:       "foo@test",
	}
	retriever := new(ManualTokenRetriever)
	err = retriever.Configure(retConfig)
	assert.Nil(t, err)
	tokenString, err := retriever.GetToken("foo")
	assert.Nil(t, err)
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(
		tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
			return pubKey, nil
		},
	)
	assert.Nil(t, err)
	assert.Equal(t, claims["aud"], "foo")
	assert.True(t, token.Valid)
}

func TestManualTokenRetriever_HMAC(t *testing.T) {
	key := "test-test-test-test-test"

	retConfig := &ManualTokenConfig{
		Key:           key,
		SigningMethod: "HS256",
		Issuer:        "https://foo",
		Subject:       "foo@test",
	}
	retriever := new(ManualTokenRetriever)
	err := retriever.Configure(retConfig)
	assert.Nil(t, err)
	tokenString, err := retriever.GetToken("foo")
	assert.Nil(t, err)
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(
		tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(key), nil
		},
	)
	assert.Nil(t, err)
	if err != nil {
		println(err.Error())
	}
	assert.Equal(t, claims["aud"], "foo")
	assert.True(t, token.Valid)

	b64Key := base64.StdEncoding.EncodeToString([]byte(key))

	retConfig = &ManualTokenConfig{
		Key:           b64Key,
		SigningMethod: "HS256",
		Issuer:        "https://foo",
		Subject:       "foo@test",
	}
	retriever = new(ManualTokenRetriever)
	err = retriever.Configure(retConfig)
	assert.Nil(t, err)
	tokenString, err = retriever.GetToken("foo")
	assert.Nil(t, err)
	claims = jwt.MapClaims{}
	token, err = jwt.ParseWithClaims(
		tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(key), nil
		},
	)
	assert.Nil(t, err)
	if err != nil {
		println(err.Error())
	}
	assert.Equal(t, claims["aud"], "foo")
	assert.True(t, token.Valid)
}

func TestManualKeyManager(t *testing.T) {
	expectedClaims := ValidatableMapClaims{
		"aud": "test-svc",
	}
	manager := NewManualKeyManager([]byte("testing"), &expectedClaims)
	validTokenString := `eyJhbGciOiJIUzI1NiIsImtpZCI6IjY1NjljN2ZkZjMzNzRkNDc4NDBlMTFmYTk3NjA5OTRhIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL3Rlc3Qtc3ZjIiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6InRlc3Qtc3ZjIiwiZXhwIjo0NTE2MjM5MDIyLCJpYXQiOjE1MTYyMzkwMjJ9.qODQNk26TSsFKrOsPqexULQh0xik0ZY_rHogvJ2Gqx8`

	v, err := manager.Validate(validTokenString)
	assert.True(t, v)
	assert.Nil(t, err)

	expiredTokenString := `eyJhbGciOiJIUzI1NiIsImtpZCI6IjY1NjljN2ZkZjMzNzRkNDc4NDBlMTFmYTk3NjA5OTRhIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoidGVzdC1zdmMiLCJleHAiOjE1MTYyMzkxMDAsImlhdCI6MTUxNjIzOTAwMH0.INfDsTNrgJ1H67Y6lYMeLWJ-g-YobgnikdOOl-tdK9U`
	v, err = manager.Validate(expiredTokenString)
	assert.False(t, v)
	assert.NotNil(t, err)
}
