// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package jwks

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	grpcAuthV1 "github.com/absmach/supermq/api/grpc/auth/v1"
	smqauth "github.com/absmach/supermq/auth"
	"github.com/absmach/supermq/auth/api/grpc/auth"
	smqjwt "github.com/absmach/supermq/auth/jwt"
	"github.com/absmach/supermq/pkg/authn"
	"github.com/absmach/supermq/pkg/errors"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
	"github.com/absmach/supermq/pkg/grpcclient"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	issuerName    = "supermq.auth"
	cacheDuration = 5 * time.Minute
)

var (
	// errJWTExpiryKey is used to check if the token is expired.
	errJWTExpiryKey = errors.New(`"exp" not satisfied`)
	// errFetchJWKS indicates an error fetching JWKS from URL.
	errFetchJWKS = errors.New("failed to fetch jwks")
	// errInvalidIssuer indicates an invalid issuer value.
	errInvalidIssuer = errors.New("invalid token issuer value")
	// ErrValidateJWTToken indicates a failure to validate JWT token.
	errValidateJWTToken = errors.New("failed to validate jwt token")

	jwksCache = struct {
		sync.RWMutex
		jwks     jwk.Set
		cachedAt time.Time
	}{}
)

var _ authn.Authentication = (*authentication)(nil)

type authentication struct {
	jwksURL       string
	authSvcClient grpcAuthV1.AuthServiceClient
}

func NewAuthentication(ctx context.Context, jwksURL string, cfg grpcclient.Config) (authn.Authentication, grpcclient.Handler, error) {
	client, err := grpcclient.NewHandler(cfg)
	if err != nil {
		return nil, nil, err
	}

	health := grpchealth.NewHealthClient(client.Connection())
	resp, err := health.Check(ctx, &grpchealth.HealthCheckRequest{
		Service: "auth",
	})
	if err != nil || resp.GetStatus() != grpchealth.HealthCheckResponse_SERVING {
		return nil, nil, grpcclient.ErrSvcNotServing
	}
	authSvcClient := auth.NewAuthClient(client.Connection(), cfg.Timeout)

	return authentication{
		jwksURL:       jwksURL,
		authSvcClient: authSvcClient,
	}, client, nil
}

func (a authentication) Authenticate(ctx context.Context, token string) (authn.Session, error) {
	if strings.HasPrefix(token, authn.PatPrefix) {
		res, err := a.authSvcClient.Authenticate(ctx, &grpcAuthV1.AuthNReq{Token: token})
		if err != nil {
			return authn.Session{}, errors.Wrap(svcerr.ErrAuthentication, err)
		}
		return authn.Session{Type: authn.PersonalAccessToken, PatID: res.GetId(), UserID: res.GetUserId(), Role: authn.Role(res.GetUserRole())}, nil
	}

	jwks, err := a.fetchJWKS(ctx)
	if err != nil {
		return authn.Session{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	tkn, err := validateToken(token, jwks)
	if err != nil {
		return authn.Session{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	key, err := smqjwt.ToKey(tkn)
	if err != nil {
		return authn.Session{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}

	return authn.Session{
		Type:     authn.AccessToken,
		UserID:   key.Subject,
		Role:     authn.Role(key.Role),
		Verified: key.Verified,
	}, nil
}

func (a authentication) fetchJWKS(ctx context.Context) (jwk.Set, error) {
	jwksCache.RLock()
	if time.Since(jwksCache.cachedAt) < cacheDuration && jwksCache.jwks.Len() > 0 {
		cached := jwksCache.jwks
		jwksCache.RUnlock()
		return cached, nil
	}
	jwksCache.RUnlock()

	req, err := http.NewRequestWithContext(ctx, "GET", a.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errFetchJWKS
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	set, err := jwk.Parse(data)
	if err != nil {
		return nil, err
	}
	jwksCache.Lock()
	jwksCache.jwks = set
	jwksCache.cachedAt = time.Now()
	jwksCache.Unlock()

	return set, nil
}

func validateToken(token string, jwks jwk.Set) (jwt.Token, error) {
	tkn, err := jwt.Parse(
		[]byte(token),
		jwt.WithValidate(true),
		jwt.WithKeySet(jwks, jws.WithInferAlgorithmFromKey(true)),
	)
	if err != nil {
		if errors.Contains(err, errJWTExpiryKey) {
			return nil, smqauth.ErrExpiry
		}
		return nil, err
	}
	validator := jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) jwt.ValidationError {
		if t.Issuer() != issuerName {
			return jwt.NewValidationError(errInvalidIssuer)
		}
		return nil
	})
	if err := jwt.Validate(tkn, jwt.WithValidator(validator)); err != nil {
		return nil, errors.Wrap(errValidateJWTToken, err)
	}

	return tkn, nil
}
