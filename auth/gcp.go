package auth

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// GcpTokenRetriever is an implementation of JwtTokenRetriever for OIDC
// identity tokens fetched using the GCP metadata service to obtain instance
// identity.
type GcpTokenRetriever struct {
	serviceAccount string
}

// A GcpTokenConfig contains configuration data used to initialize and
// validate a GcpTokenRetriever object.
type GcpTokenConfig struct {
	ServiceAccount string `long:"service-account" env:"SERVICE_ACCOUNT" description:"GCP instance identity name" default:"default"`
}

// GetToken retrieves a new token from the metadata identity service.
func (r *GcpTokenRetriever) GetToken(aud string) (string, error) {
	client := http.Client{
		Timeout: 30 * time.Second,
	}
	url := fmt.Sprintf("http://metadata/computeMetadata/v1/instance/service-accounts/%v/identity?audience=%v", r.serviceAccount, aud)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("error creating identity request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch token: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unsuccessful status code while fetching token: %v, %v", resp.StatusCode, body)
	}

	return string(body), nil
}

// Configure will take a valid GcpTokenConfig and use it to configure the token retriever.
func (r *GcpTokenRetriever) Configure(config interface{}) error {
	c, ok := config.(*GcpTokenConfig)
	if !ok {
		log.Fatalln("internal error: incorrect Token config")
	}
	if c.ServiceAccount == "" {
		return errors.New("GCP service account name must not be empty")
	}

	r.serviceAccount = c.ServiceAccount
	return nil
}
