package configuration

import (
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

func LoadKeys(privateKeyPath string, publicKeyPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, nil, err
	}

	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse public key: %w", err)
	}

	equal := privateKey.PublicKey.Equal(publicKey)
	if !equal {
		return nil, nil, fmt.Errorf("private key does not match public key")
	}

	return privateKey, publicKey, nil
}
