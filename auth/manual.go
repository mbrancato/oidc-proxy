package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// ManualTokenRetriever is an implementation of JwtTokenRetriever for OIDC
// identity tokens created manually using a user-provided key.
type ManualTokenRetriever struct {
	issuer  string
	subject string
	key     interface{}
	signing jwt.SigningMethod
	claims  jwt.MapClaims
}

// A ManualTokenConfig contains configuration data used to initialize and
// validate a ManualTokenRetriever object.
type ManualTokenConfig struct {
	Issuer        string `long:"issuer" env:"ISSUER" description:"Manual authentication issuer claim"`
	Subject       string `long:"subject" env:"SUBJECT" description:"Manual authentication subject claim"`
	Key           string `long:"signing-key" env:"SIGNING_KEY" description:"Manual authentication signing key"`
	SigningMethod string `long:"signing-method" env:"SIGNING_METHOD" description:"Manual authentication signing method"`
	Claims        string `long:"claims" env:"CLAIMS" description:"Manual authentication additional claims"`
}

// A ManualKeyManager implements the KeyManager interface and supports manual
// key assignment for JWT validation. It supports both RSA public keys and
// HMAC secrets.
type ManualKeyManager struct {
	key            interface{}
	expectedClaims *ValidatableMapClaims
}

// GetToken generates a new token from the provided audience, claims, and private key.
func (r *ManualTokenRetriever) GetToken(aud string) (string, error) {
	token := jwt.New(r.signing)
	claims := token.Claims.(jwt.MapClaims)
	now := time.Now()
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(1 * time.Hour).Unix()
	claims["aud"] = aud
	claims["iss"] = r.issuer
	claims["sub"] = r.subject

	for k, v := range r.claims {
		claims[k] = v
	}

	signedToken, err := token.SignedString(r.key)

	return signedToken, err
}

// Configure will take a valid ManualTokenConfig and use it to configure the token retriever.
func (r *ManualTokenRetriever) Configure(config interface{}) error {
	c, ok := config.(*ManualTokenConfig)
	if !ok {
		log.Fatalln("internal error: incorrect token config")
	}
	if c.Key == "" {
		return errors.New("key must not be empty")
	}
	if c.SigningMethod == "" {
		return errors.New("signing method must not be empty")
	}
	if c.Subject == "" {
		return errors.New("subject must not be empty")
	}
	if c.Issuer == "" {
		return errors.New("issuer must not be empty")
	}

	key, err := detectManualKey([]byte(c.Key), strings.ToUpper(c.SigningMethod))
	if err != nil {
		return fmt.Errorf("unable to detect signing token: %w", err)
	}
	r.key = key

	r.signing = jwt.GetSigningMethod(strings.ToUpper(c.SigningMethod))
	if r.signing == nil {
		return errors.New("unknown signing method was specified")
	}

	r.issuer = c.Issuer
	if r.issuer == "" {
		return errors.New("issuer must be specified when using the manual auth type")
	}
	r.subject = c.Subject
	if r.subject == "" {
		return errors.New("subject must be specified when using the manual auth type")
	}

	claims, err := ConvertClaimString(c.Claims)
	if err != nil {
		log.Fatalf("error parsing manual claims: %v\n", err)
	}

	if claims == nil {
		claims = new(jwt.MapClaims)
	}

	for _, k := range getReservedClaims() {
		if _, ok := (*claims)[k]; ok {
			log.Fatalf("reserved claim must be specified in config: %v\n", k)
		}
	}
	r.claims = *claims

	return nil
}

// detectManualKey attempts to detect the key-type provided for manual JWT
// creation and signing.
func detectManualKey(b []byte, m string) (interface{}, error) {
	if strings.HasPrefix(m, "RS") {
		privKey, err := jwt.ParseRSAPrivateKeyFromPEM(b)
		if err == nil {
			log.Println("detected RSA private token")
			return privKey, nil
		}
	}

	if strings.HasPrefix(m, "HS") {
		decodedKey, err := base64.StdEncoding.DecodeString(string(b))
		if err == nil {
			log.Println("detected base64-encoded symmetric token")
			return decodedKey, nil
		}

		log.Println("detected raw symmetric token")
		return b, nil
	}
	return nil, errors.New("no appropriate token detected for signing method")
}

// Validate will parse and validate a JWT token and its claims.
func (m *ManualKeyManager) Validate(tok string) (bool, error) {
	claims := jwt.MapClaims{}
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return m.key, nil
	}
	_, err := jwt.ParseWithClaims(
		tok, &claims, keyFunc,
	)
	if err != nil {
		return false, err
	}

	return m.expectedClaims.ValidateClaims(&claims)
}

// NewManualKeyManager returns a new ManualKeyManager for the specified key.
func NewManualKeyManager(key interface{}, claims *ValidatableMapClaims) *ManualKeyManager {
	m := ManualKeyManager{
		key:            key,
		expectedClaims: claims,
	}

	return &m
}

// getReservedClaims returns a list of claims that can not be specified as
// additional claims for validation,
func getReservedClaims() []string {
	return []string{"iat", "exp", "iss", "aud", "sub"}
}
