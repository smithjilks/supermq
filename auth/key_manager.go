// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	ErrUnsupportedKeyAlgorithm = errors.New("unsupported key algorithm")
	ErrInvalidSymmetricKey     = errors.New("invalid symmetric key")
)

// JWK represents a JSON Web Key.
type JWK struct {
	key jwk.Key
}

// NewJWK creates a new JWK from a jwk.Key.
func NewJWK(key jwk.Key) JWK {
	return JWK{key: key}
}

// Key returns the underlying jwk.Key.
func (j JWK) Key() jwk.Key {
	return j.key
}

// KeyManager represents a manager for JWT keys.
type KeyManager interface {
	SignJWT(token jwt.Token) ([]byte, error)

	ParseJWT(token string) (jwt.Token, error)

	PublicJWKS() []JWK
}

func IsSymmetricAlgorithm(alg string) (bool, error) {
	switch alg {
	case "HS256", "HS384", "HS512":
		return true, nil
	case "EdDSA":
		return false, nil
	default:
		return false, ErrUnsupportedKeyAlgorithm
	}
}
