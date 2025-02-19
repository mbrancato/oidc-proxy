package auth

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	OidcStandardClaims = []string{
		"sub", "name", "given_name", "family_name", "middle_name", "nickname",
		"preferred_username", "profile", "picture", "website", "email", "email_verified", "gender", "birthdate",
		"zoneinfo", "locale", "phone_number", "phone_number_verified", "address", "updated_at",
	}
	OidcIdTokenClaimsRequired = []string{"iss", "sub", "aud", "exp", "iat"}
	OidcIdTokenExtraClaims    = []string{"auth_time", "nonce", "acr", "azp", "at_hash", "c_hash"}
	OidcIdTokenClaims         = append(
		OidcIdTokenClaimsRequired, append(
			OidcStandardClaims,
			OidcIdTokenExtraClaims...,
		)...,
	)
)

// A JwtTokenRetriever is an abstract interface that is designed to allow a
// JwtManager to pull a new token from JwtTokenRetriever implementations. Each
// implementation may use a specific configuration struct, which is passed to
// the Configure method. After initialization, the Configure method must be
// called, which will validate the specific configuration for the token
// retriever type specified. Afterwards, the GetToken method will fetch a
// valid JWT token.
type JwtTokenRetriever interface {
	GetToken(aud string) (string, error)
	Configure(config interface{}) error
}

// A KeyManager is an abstract interface that allows for JWT validation. Each
// implementation must implement the Validate method to confirm both JWT
// signature and claims.
//
// Each implementation should provide an initialization function that may
// be supplied with a ValidatableMapClaims object which is used for
// performing authorization.
type KeyManager interface {
	Validate(tok string) (bool, error)
}

// The JwtManager manages JWT retrieval and renewal. It fetches tokens from
// JwtTokenRetriever implementations.
type JwtManager struct {
	token      string
	renewAfter time.Time
	method     JwtTokenRetriever
}

// The ValidatableMapClaims represents JWT claims are used to validate claims
// presented by a jwt.MapClaims object.
type ValidatableMapClaims jwt.MapClaims

// Token will fetch JWT tokens from a JwtTokenRetriever. On first use, an
// initial token will be fetched. On subsequent usage, a new token will be
// fetched if the token is expiring soon.
func (m *JwtManager) Token(aud string) (string, error) {
	if m.token == "" || time.Now().After(m.renewAfter) {
		ts, err := m.method.GetToken(aud)
		if err != nil {
			return "", err
		}

		parser := new(jwt.Parser)
		claims := jwt.MapClaims{}
		_, _, err = parser.ParseUnverified(ts, &claims)
		if err != nil {
			return "", fmt.Errorf("unable to parse JWT: %w", err)
		}

		oidcClaims, err := validateOidcRequiredClaims(&claims)
		if oidcClaims {
			expClaim, ok := claims["exp"].(float64)
			if !ok {
				return "", fmt.Errorf("unable to access token expiration")
			}
			now := time.Now()
			exp := time.Unix(int64(expClaim), 0)
			m.renewAfter = time.Unix(now.Unix()+(exp.Unix()-now.Unix()), 0)
			m.token = ts
		} else {
			return "", fmt.Errorf("unable to get standard JWT Token claims: %w", err)
		}
	}

	return m.token, nil
}

// NewJwtManager returns a new JwtManager with the supplied JwtTokenRetriever
// implementation.
func NewJwtManager(method JwtTokenRetriever) JwtManager {
	return JwtManager{
		method: method,
	}
}

// ValidateClaims takes a set of unverified jwt.MapClaims and confirms that
// all claims match specified requirements for validation in the
// ValidateClaims object.
func (c ValidatableMapClaims) ValidateClaims(requestClaims *jwt.MapClaims) (bool, error) {
	oidcClaims, err := validateOidcRequiredClaims(requestClaims)
	if !oidcClaims {
		return false, err
	}

	if _, ok := c["aud"]; !ok {
		return false, errors.New("internal error: audience claim was missing from expected claims")
	}

	for k, v := range c {
		cv, ok := (*requestClaims)[k]
		if !ok {
			return false, fmt.Errorf("request is missing claim: %v", k)
		}
		switch i := v.(type) {
		case *regexp.Regexp:
			j, ok := cv.(string)
			if !ok {
				return false, fmt.Errorf("claim must be a string: %v", k)
			} else if !i.MatchString(j) {
				return false, fmt.Errorf("claim was not valid: %v", k)
			}
		case []string:
			// Only 'aud' and 'amr' may be arrays of strings. Make sure all other OIDC claims are
			// not in here.
			if k != "aud" && k != "amr" {
				if slices.Contains(OidcIdTokenClaims, k) {
					return false, fmt.Errorf("claim did not match expected value: %v", k)
				}
			}

			// aud supports a list of audiences that are valid. We enforce strict order checking
			// for this claim.
			if k == "aud" {
				audExists := false
				for a := range i {
					if cv == a {
						audExists = true
					}
				}

				if !audExists {
					return false, fmt.Errorf("claim did not match expected value: %v", k)
				}
			}

			// For other claims, the set of values must be equal, but order is ignored.
			if !equivalentSet(i, cv.([]string)) {
				return false, fmt.Errorf("claim did not match expected value: %v", k)
			}

			return true, nil
		default:
			if reflect.TypeOf(cv) != reflect.TypeOf(v) {
				return false, fmt.Errorf("claim did not match expected type: %v", k)
			}
			if cv != v {
				return false, fmt.Errorf("claim did not match expected value: %v", k)
			}
		}
	}
	return true, nil
}

// AddClaim will add a required claim for validation.
func (c ValidatableMapClaims) AddClaim(k string, v interface{}) {
	c[k] = v
}

// HasClaim returns true if the ValidatableMapClaims has a specific claim.
func (c ValidatableMapClaims) HasClaim(k string) bool {
	_, ok := c[k]
	return ok
}

// validateOidcRequiredClaims will validate that claims presented by a JWT
// include all the required claims for an OIDC identity token.
func validateOidcRequiredClaims(claims *jwt.MapClaims) (bool, error) {
	c := *claims
	if _, ok := c["aud"]; !ok {
		return false, errors.New("audience claim was missing from ID token")
	}

	if _, ok := c["iat"]; !ok {
		return false, errors.New("issued at claim was missing from ID token")
	}

	if _, ok := c["exp"]; !ok {
		return false, errors.New("expiration claim was missing from ID token")
	}

	if _, ok := c["sub"]; !ok {
		return false, errors.New("subject claim was missing from ID token")
	}

	if _, ok := c["iss"]; !ok {
		return false, errors.New("issuer claim was missing from ID token")
	}
	return true, nil
}

// areEqualIgnoreOrder checks if two string slices contain the same elements, ignoring order
func equivalentSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	// probably a little slower, but this bidirectional check is simple
	for _, v := range a {
		if !slices.Contains(b, v) {
			return false
		}
	}

	for _, v := range b {
		if !slices.Contains(a, v) {
			return false
		}
	}

	return true
}
