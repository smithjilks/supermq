// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package asymmetric

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"github.com/absmach/supermq"
	"github.com/absmach/supermq/auth"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	errLoadingPrivateKey = errors.New("failed to load private key")
	errInvalidKeySize    = errors.New("invalid ED25519 key size")
	errParsingPrivateKey = errors.New("failed to parse private key")
	errInvalidKeyType    = errors.New("private key is not ED25519")
	errGeneratingKID     = errors.New("failed to generate key ID")
)

type manager struct {
	privateKey jwk.Key
	publicKey  jwk.Key
	kid        string
}

var _ auth.KeyManager = (*manager)(nil)

// NewKeyManager creates a new asymmetric key manager that loads the private key from a file.
func NewKeyManager(privateKeyPath string, idProvider supermq.IDProvider) (auth.KeyManager, error) {
	kid, err := idProvider.ID()
	if err != nil {
		return nil, errors.Join(errGeneratingKID, err)
	}

	privateJwk, publicJwk, err := loadKeyPair(privateKeyPath, kid)
	if err != nil {
		return nil, err
	}

	return &manager{
		privateKey: privateJwk,
		publicKey:  publicJwk,
		kid:        kid,
	}, nil
}

func (km *manager) SignJWT(token jwt.Token) ([]byte, error) {
	return jwt.Sign(token, jwt.WithKey(jwa.EdDSA, km.privateKey))
}

func (km *manager) ParseJWT(token string) (jwt.Token, error) {
	set := jwk.NewSet()
	if err := set.AddKey(km.publicKey); err != nil {
		return nil, err
	}

	tkn, err := jwt.Parse(
		[]byte(token),
		jwt.WithValidate(true),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
	)
	if err != nil {
		return nil, err
	}
	return tkn, nil
}

func (km *manager) PublicJWKS() []auth.JWK {
	return []auth.JWK{auth.NewJWK(km.publicKey)}
}

func loadKeyPair(privateKeyPath string, kid string) (jwk.Key, jwk.Key, error) {
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, nil, errors.Join(errLoadingPrivateKey, err)
	}

	var privateKey ed25519.PrivateKey
	block, _ := pem.Decode(privateKeyBytes)
	switch {
	case block != nil:
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, errors.Join(errParsingPrivateKey, err)
		}
		var ok bool
		privateKey, ok = parsedKey.(ed25519.PrivateKey)
		if !ok {
			return nil, nil, errInvalidKeyType
		}
	default:
		if len(privateKeyBytes) != ed25519.PrivateKeySize {
			return nil, nil, errInvalidKeySize
		}
		privateKey = ed25519.PrivateKey(privateKeyBytes)
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)

	privateJwk, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, nil, err
	}
	if err := privateJwk.Set(jwk.AlgorithmKey, jwa.EdDSA); err != nil {
		return nil, nil, err
	}
	if err := privateJwk.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, nil, err
	}

	publicJwk, err := jwk.FromRaw(publicKey)
	if err != nil {
		return nil, nil, err
	}
	if err := publicJwk.Set(jwk.AlgorithmKey, jwa.EdDSA); err != nil {
		return nil, nil, err
	}
	if err := publicJwk.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, nil, err
	}

	return privateJwk, publicJwk, nil
}
