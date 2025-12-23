// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package symmetric

import (
	"github.com/absmach/supermq/auth"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type manager struct {
	algorithm jwa.KeyAlgorithm
	secret    []byte
}

var _ auth.KeyManager = (*manager)(nil)

func NewKeyManager(algorithm string, secret []byte) (auth.KeyManager, error) {
	alg := jwa.KeyAlgorithmFrom(algorithm)
	if _, ok := alg.(jwa.InvalidKeyAlgorithm); ok {
		return nil, auth.ErrUnsupportedKeyAlgorithm
	}
	if len(secret) == 0 {
		return nil, auth.ErrInvalidSymmetricKey
	}
	return &manager{
		secret:    secret,
		algorithm: alg,
	}, nil
}

func (km *manager) SignJWT(token jwt.Token) ([]byte, error) {
	return jwt.Sign(token, jwt.WithKey(km.algorithm, km.secret))
}

func (km *manager) ParseJWT(token string) (jwt.Token, error) {
	return jwt.Parse(
		[]byte(token),
		jwt.WithValidate(true),
		jwt.WithKey(km.algorithm, km.secret),
	)
}

func (km *manager) PublicJWKS() []auth.JWK {
	return nil
}
