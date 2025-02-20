package auth

import (
	"regexp"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	_, err = jwt.ParseWithClaims(
		tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte("testing"), nil
		},
	)
	assert.Nil(t, err)
	assert.Equal(t, claims["aud"], "foo")
}

func TestValidatableMapClaims_ValidateClaims(t *testing.T) {
	tests := []struct {
		name           string
		expectedClaims ValidatableMapClaims
		requestClaims  jwt.MapClaims
		success        bool
	}{
		{
			name: "valid claims",
			expectedClaims: ValidatableMapClaims{
				"aud": "test-aud",
				"iss": "test-iss",
				"sub": "test-sub",
			},
			requestClaims: jwt.MapClaims{
				"aud": "test-aud",
				"iss": "test-iss",
				"sub": "test-sub",
				"exp": time.Now().Add(time.Minute).Unix(),
				"iat": time.Now().Unix(),
			},
			success: true,
		},
		{
			name: "missing sub",
			expectedClaims: ValidatableMapClaims{
				"aud": "test-aud",
				"iss": "test-iss",
				"sub": "test-sub",
			},
			requestClaims: jwt.MapClaims{
				"aud": "test-aud",
				"iss": "test-iss",
				"exp": time.Now().Add(time.Minute).Unix(),
				"iat": time.Now().Unix(),
			},
			success: false,
		},
		{
			name: "missing arbitrary claim",
			expectedClaims: ValidatableMapClaims{
				"aud":    "test-aud",
				"iss":    "test-iss",
				"sub":    "test-sub",
				"target": "test-target",
			},
			requestClaims: jwt.MapClaims{
				"aud": "test-aud",
				"iss": "test-iss",
				"sub": "test-sub",
				"exp": time.Now().Add(time.Minute).Unix(),
				"iat": time.Now().Unix(),
			},
			success: false,
		},
		{
			name: "missing iat",
			expectedClaims: ValidatableMapClaims{
				"aud": "test-aud",
				"iss": "test-iss",
				"sub": "test-sub",
			},
			requestClaims: jwt.MapClaims{
				"aud": "test-aud",
				"iss": "test-iss",
				"sub": "test-sub",
				"exp": time.Now().Add(time.Minute).Unix(),
			},
			success: false,
		},
		{
			name: "missing exp",
			expectedClaims: ValidatableMapClaims{
				"aud": "test-aud",
				"iss": "test-iss",
				"sub": "test-sub",
			},
			requestClaims: jwt.MapClaims{
				"aud": "test-aud",
				"iss": "test-iss",
				"sub": "test-sub",
				"iat": time.Now().Unix(),
			},
			success: false,
		},
		{
			name: "regex claim match",
			expectedClaims: ValidatableMapClaims{
				"aud": regexp.MustCompile(`^test-aud$`),
			},
			requestClaims: jwt.MapClaims{
				"aud": "test-aud",
				"iss": "test-iss",
				"sub": "test-sub",
				"exp": time.Now().Add(time.Minute).Unix(),
				"iat": time.Now().Unix(),
			},
			success: true,
		},
		{
			name: "regex claim mismatch",
			expectedClaims: ValidatableMapClaims{
				"aud": regexp.MustCompile(`^test-aud$`),
			},
			requestClaims: jwt.MapClaims{
				"aud": "invalid-aud",
				"iss": "test-iss",
				"sub": "test-sub",
				"exp": time.Now().Add(time.Minute).Unix(),
				"iat": time.Now().Unix(),
			},
			success: false,
		},
		{
			name: "array mismatch",
			expectedClaims: ValidatableMapClaims{
				"aud":    "test-aud",
				"groups": []string{"group1", "group2"},
			},
			requestClaims: jwt.MapClaims{
				"aud":    "test-aud",
				"iss":    "test-iss",
				"sub":    "test-sub",
				"groups": []string{"group1", "group2", "group3"},
				"exp":    time.Now().Add(time.Minute).Unix(),
				"iat":    time.Now().Unix(),
			},
			success: false,
		},
		{
			name: "array match",
			expectedClaims: ValidatableMapClaims{
				"aud":    "test-aud",
				"groups": []string{"group1", "group2"},
			},
			requestClaims: jwt.MapClaims{
				"aud":    "test-aud",
				"iss":    "test-iss",
				"sub":    "test-sub",
				"groups": []string{"group1", "group2"},
				"exp":    time.Now().Add(time.Minute).Unix(),
				"iat":    time.Now().Unix(),
			},
			success: true,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				res, err := tt.expectedClaims.ValidateClaims(&tt.requestClaims)
				if tt.success {
					assert.NoError(t, err)
					assert.True(t, res)
				} else {
					assert.Error(t, err)
					assert.False(t, res)
				}
			},
		)
	}
}
