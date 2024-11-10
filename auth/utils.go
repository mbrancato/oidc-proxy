package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"gopkg.in/yaml.v3"
)

func ConvertClaimString(claimString string) (*jwt.MapClaims, error) {
	var claimMap map[string]interface{}
	if claimString == "" {
		return nil, nil
	}

	claimString = strings.TrimSpace(claimString)
	err := json.Unmarshal([]byte(claimString), &claimMap)
	if err == nil {
		log.Println("detected JSON claim map")
		return ConvertClaims(claimMap)
	}

	err = yaml.Unmarshal([]byte(claimString), &claimMap)
	if err == nil {
		log.Println("detected YAML claim map")
		return ConvertClaims(claimMap)
	}

	return nil, errors.New("unable to decode claim map")
}

func ConvertValidatableClaimString(claimString string) (*ValidatableMapClaims, error) {
	claimMap, err := ConvertClaimString(claimString)
	if err != nil {
		return nil, fmt.Errorf("error converting claim stream: %w", err)
	}

	if claimMap == nil {
		return &ValidatableMapClaims{}, nil
	}

	return convertClaimsToValidatableClaims(*claimMap)
}

func ConvertClaims(claimMap map[string]interface{}) (*jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	for k, v := range claimMap {
		switch i := v.(type) {
		case float64:
			claims[k] = i
		case bool:
			claims[k] = i
		case nil:
			claims[k] = i
		case string:
			claims[k] = i
		default:
			return nil, fmt.Errorf("unsupported type for claim key: %v\n", k)
		}
	}

	return &claims, nil
}

func convertClaimsToValidatableClaims(claimMap jwt.MapClaims) (*ValidatableMapClaims, error) {
	claims := ValidatableMapClaims{}
	for k, v := range claimMap {
		switch i := v.(type) {
		case string:
			reg, err := regexp.Compile(i)
			if err != nil {
				return nil, fmt.Errorf("unable to compile regular expression from string: %v\n", i)
			}
			claims[k] = reg
		default:
			claims[k] = i
		}

	}

	return &claims, nil
}
