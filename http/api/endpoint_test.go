// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/absmach/mgate"
	proxy "github.com/absmach/mgate/pkg/http"
	"github.com/absmach/mgate/pkg/session"
	grpcChannelsV1 "github.com/absmach/supermq/api/grpc/channels/v1"
	grpcClientsV1 "github.com/absmach/supermq/api/grpc/clients/v1"
	grpcCommonV1 "github.com/absmach/supermq/api/grpc/common/v1"
	grpcDomainsV1 "github.com/absmach/supermq/api/grpc/domains/v1"
	apiutil "github.com/absmach/supermq/api/http/util"
	chmocks "github.com/absmach/supermq/channels/mocks"
	climocks "github.com/absmach/supermq/clients/mocks"
	dmocks "github.com/absmach/supermq/domains/mocks"
	server "github.com/absmach/supermq/http"
	"github.com/absmach/supermq/http/api"
	"github.com/absmach/supermq/internal/testsutil"
	smqlog "github.com/absmach/supermq/logger"
	smqauthn "github.com/absmach/supermq/pkg/authn"
	authnMocks "github.com/absmach/supermq/pkg/authn/mocks"
	"github.com/absmach/supermq/pkg/connections"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
	"github.com/absmach/supermq/pkg/messaging"
	pubsub "github.com/absmach/supermq/pkg/messaging/mocks"
	"github.com/absmach/supermq/pkg/policies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	instanceID   = "5de9b29a-feb9-11ed-be56-0242ac120002"
	invalidValue = "invalid"
)

var (
	clientID = testsutil.GenerateUUID(&testing.T{})
	chanID   = testsutil.GenerateUUID(&testing.T{})
	domainID = testsutil.GenerateUUID(&testing.T{})
	userID   = testsutil.GenerateUUID(&testing.T{})
)

func newService(authn smqauthn.Authentication, clients grpcClientsV1.ClientsServiceClient, channels grpcChannelsV1.ChannelsServiceClient, domains grpcDomainsV1.DomainsServiceClient) (session.Handler, *pubsub.PubSub, error) {
	pub := new(pubsub.PubSub)
	parser, err := messaging.NewTopicParser(messaging.DefaultCacheConfig, channels, domains)
	if err != nil {
		return nil, nil, err
	}

	return server.NewHandler(pub, authn, clients, channels, parser, smqlog.NewMock()), pub, nil
}

func newTargetHTTPServer() *httptest.Server {
	mux := api.MakeHandler(smqlog.NewMock(), instanceID)
	return httptest.NewServer(mux)
}

func newProxyHTPPServer(svc session.Handler, targetServer *httptest.Server) (*httptest.Server, error) {
	ptUrl, _ := url.Parse(targetServer.URL)
	ptHost, ptPort, _ := net.SplitHostPort(ptUrl.Host)
	config := mgate.Config{
		Host:           "",
		Port:           "",
		PathPrefix:     "",
		TargetHost:     ptHost,
		TargetPort:     ptPort,
		TargetProtocol: ptUrl.Scheme,
		TargetPath:     ptUrl.Path,
	}
	mp, err := proxy.NewProxy(config, svc, smqlog.NewMock(), []string{}, []string{})
	if err != nil {
		return nil, err
	}
	return httptest.NewServer(http.HandlerFunc(mp.ServeHTTP)), nil
}

type testRequest struct {
	client      *http.Client
	method      string
	url         string
	contentType string
	token       string
	body        io.Reader
	basicAuth   bool
	bearerToken bool
}

func (tr testRequest) make() (*http.Response, error) {
	req, err := http.NewRequest(tr.method, tr.url, tr.body)
	if err != nil {
		return nil, err
	}

	if tr.token != "" {
		switch {
		case tr.basicAuth:
			req.SetBasicAuth("", apiutil.ClientPrefix+tr.token)
		case tr.bearerToken:
			req.Header.Set("Authorization", apiutil.BearerPrefix+tr.token)
		default:
			req.Header.Set("Authorization", apiutil.ClientPrefix+tr.token)
		}
	}
	if tr.contentType != "" {
		req.Header.Set("Content-Type", tr.contentType)
	}
	return tr.client.Do(req)
}

func TestPublish(t *testing.T) {
	clients := new(climocks.ClientsServiceClient)
	authn := new(authnMocks.Authentication)
	channels := new(chmocks.ChannelsServiceClient)
	domains := new(dmocks.DomainsServiceClient)
	ctSenmlJSON := "application/senml+json"
	ctSenmlCBOR := "application/senml+cbor"
	ctJSON := "application/json"
	clientKey := "client_key"
	invalidKey := invalidValue
	validToken := "token"
	invalidToken := "invalid_token"
	msg := `[{"n":"current","t":-1,"v":1.6}]`
	msgJSON := `{"field1":"val1","field2":"val2"}`
	msgCBOR := `81A3616E6763757272656E746174206176FB3FF999999999999A`
	svc, pub, err := newService(authn, clients, channels, domains)
	assert.Nil(t, err, fmt.Sprintf("failed to create service with err: %v", err))
	target := newTargetHTTPServer()
	defer target.Close()
	ts, err := newProxyHTPPServer(svc, target)
	assert.Nil(t, err, fmt.Sprintf("failed to create proxy server with err: %v", err))

	defer ts.Close()

	cases := []struct {
		desc        string
		domainID    string
		chanID      string
		clientID    string
		clientType  string
		msg         string
		contentType string
		key         string
		status      int
		basicAuth   bool
		bearerToken bool
		authnErr    error
		authnRes    *grpcClientsV1.AuthnRes
		authnRes1   smqauthn.Session
		authzRes    *grpcChannelsV1.AuthzRes
		authzErr    error
		err         error
	}{
		{
			desc:        "publish message successfully",
			domainID:    domainID,
			chanID:      chanID,
			clientID:    clientID,
			msg:         msg,
			contentType: ctSenmlJSON,
			key:         clientKey,
			status:      http.StatusAccepted,
			authnRes:    &grpcClientsV1.AuthnRes{Id: clientID, Authenticated: true},
			authzRes:    &grpcChannelsV1.AuthzRes{Authorized: true},
		},
		{
			desc:        "publish message with application/senml+cbor content-type",
			domainID:    domainID,
			chanID:      chanID,
			clientID:    clientID,
			msg:         msgCBOR,
			contentType: ctSenmlCBOR,
			key:         clientKey,
			status:      http.StatusAccepted,
			authnRes:    &grpcClientsV1.AuthnRes{Id: clientID, Authenticated: true},
			authzRes:    &grpcChannelsV1.AuthzRes{Authorized: true},
		},
		{
			desc:        "publish message with application/json content-type",
			domainID:    domainID,
			chanID:      chanID,
			clientID:    clientID,
			msg:         msgJSON,
			contentType: ctJSON,
			key:         clientKey,
			status:      http.StatusAccepted,
			authnRes:    &grpcClientsV1.AuthnRes{Id: clientID, Authenticated: true},
			authzRes:    &grpcChannelsV1.AuthzRes{Authorized: true},
		},
		{
			desc:        "publish message with empty key",
			domainID:    domainID,
			chanID:      chanID,
			clientID:    clientID,
			msg:         msg,
			contentType: ctSenmlJSON,
			key:         "",
			status:      http.StatusBadRequest,
		},
		{
			desc:        "publish message with basic auth",
			domainID:    domainID,
			chanID:      chanID,
			clientID:    clientID,
			msg:         msg,
			contentType: ctSenmlJSON,
			key:         clientKey,
			basicAuth:   true,
			status:      http.StatusAccepted,
			authnRes:    &grpcClientsV1.AuthnRes{Id: clientID, Authenticated: true},
			authzRes:    &grpcChannelsV1.AuthzRes{Authorized: true},
		},
		{
			desc:        "publish message with invalid key",
			domainID:    domainID,
			chanID:      chanID,
			clientID:    clientID,
			msg:         msg,
			contentType: ctSenmlJSON,
			key:         invalidKey,
			status:      http.StatusUnauthorized,
			authnRes:    &grpcClientsV1.AuthnRes{Authenticated: false},
		},
		{
			desc:        "publish message with invalid basic auth",
			domainID:    domainID,
			chanID:      chanID,
			clientID:    clientID,
			msg:         msg,
			contentType: ctSenmlJSON,
			key:         invalidKey,
			basicAuth:   true,
			status:      http.StatusUnauthorized,
			authnRes:    &grpcClientsV1.AuthnRes{Authenticated: false},
		},
		{
			desc:        "publish message with valid bearer token",
			domainID:    domainID,
			chanID:      chanID,
			clientID:    userID,
			msg:         msg,
			contentType: ctSenmlJSON,
			key:         validToken,
			bearerToken: true,
			status:      http.StatusAccepted,
			authnRes1:   smqauthn.Session{UserID: userID},
			authzRes:    &grpcChannelsV1.AuthzRes{Authorized: true},
		},
		{
			desc:        "publish message with invalid bearer token",
			domainID:    domainID,
			chanID:      chanID,
			clientID:    userID,
			msg:         msg,
			contentType: ctSenmlJSON,
			key:         invalidToken,
			bearerToken: true,
			status:      http.StatusUnauthorized,
			authnRes1:   smqauthn.Session{},
			authnErr:    svcerr.ErrAuthentication,
		},
		{
			desc:        "publish message without content type",
			domainID:    domainID,
			chanID:      chanID,
			clientID:    clientID,
			msg:         msg,
			contentType: "",
			key:         clientKey,
			status:      http.StatusUnsupportedMediaType,
			authnRes:    &grpcClientsV1.AuthnRes{Id: clientID, Authenticated: true},
			authzRes:    &grpcChannelsV1.AuthzRes{Authorized: true},
		},
		{
			desc:        "publish message to empty channel",
			domainID:    domainID,
			chanID:      "",
			clientID:    clientID,
			msg:         msg,
			contentType: ctSenmlJSON,
			key:         clientKey,
			status:      http.StatusBadRequest,
			authnRes:    &grpcClientsV1.AuthnRes{Id: clientID, Authenticated: true},
			authzRes:    &grpcChannelsV1.AuthzRes{Authorized: false},
		},
		{
			desc:        "publish message with invalid domain ID",
			domainID:    invalidValue,
			chanID:      chanID,
			clientID:    clientID,
			msg:         msg,
			contentType: ctSenmlJSON,
			key:         clientKey,
			status:      http.StatusUnauthorized,
			authnRes:    &grpcClientsV1.AuthnRes{Id: clientID, Authenticated: true},
			authzRes:    &grpcChannelsV1.AuthzRes{Authorized: false},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			clientsCall := clients.On("Authenticate", mock.Anything, &grpcClientsV1.AuthnReq{Token: smqauthn.AuthPack(smqauthn.DomainAuth, tc.domainID, tc.key)}).Return(tc.authnRes, tc.authnErr)
			authCall := authn.On("Authenticate", mock.Anything, tc.key).Return(tc.authnRes1, tc.authnErr)
			domainsCall := domains.On("RetrieveIDByRoute", mock.Anything, mock.Anything).Return(&grpcCommonV1.RetrieveEntityRes{Entity: &grpcCommonV1.EntityBasic{Id: tc.domainID}}, nil)
			tc.clientType = policies.ClientType
			if tc.bearerToken {
				tc.clientType = policies.UserType
			}
			channelsCall := channels.On("Authorize", mock.Anything, &grpcChannelsV1.AuthzReq{
				DomainId:   tc.domainID,
				ChannelId:  tc.chanID,
				ClientId:   tc.clientID,
				ClientType: tc.clientType,
				Type:       uint32(connections.Publish),
			}).Return(tc.authzRes, tc.authzErr)
			svcCall := pub.On("Publish", mock.Anything, messaging.EncodeTopicSuffix(tc.domainID, tc.chanID, ""), mock.Anything).Return(nil)
			req := testRequest{
				client:      ts.Client(),
				method:      http.MethodPost,
				url:         fmt.Sprintf("%s/m/%s/c/%s", ts.URL, tc.domainID, tc.chanID),
				contentType: tc.contentType,
				token:       tc.key,
				body:        strings.NewReader(tc.msg),
				basicAuth:   tc.basicAuth,
				bearerToken: tc.bearerToken,
			}
			res, err := req.make()
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
			assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))
			svcCall.Unset()
			clientsCall.Unset()
			authCall.Unset()
			channelsCall.Unset()
			domainsCall.Unset()
		})
	}
}

func TestHealthCheck(t *testing.T) {
	clients := new(climocks.ClientsServiceClient)
	authn := new(authnMocks.Authentication)
	channels := new(chmocks.ChannelsServiceClient)
	domains := new(dmocks.DomainsServiceClient)
	clientKey := "client_key"
	invalidKey := invalidValue
	validToken := "token"
	invalidToken := "invalid_token"
	svc, _, err := newService(authn, clients, channels, domains)
	assert.Nil(t, err, fmt.Sprintf("failed to create service with err: %v", err))
	target := newTargetHTTPServer()
	defer target.Close()
	ts, err := newProxyHTPPServer(svc, target)
	assert.Nil(t, err, fmt.Sprintf("failed to create proxy server with err: %v", err))

	defer ts.Close()

	cases := []struct {
		desc        string
		domainID    string
		clientID    string
		clientType  string
		key         string
		status      int
		basicAuth   bool
		bearerToken bool
		authnErr    error
		authnRes    *grpcClientsV1.AuthnRes
		authnRes1   smqauthn.Session
	}{
		{
			desc:     "health check successfully",
			domainID: domainID,
			key:      clientKey,
			status:   http.StatusOK,
			authnRes: &grpcClientsV1.AuthnRes{Id: clientID, Authenticated: true},
		},
		{
			desc:      "health check with basic auth",
			domainID:  domainID,
			key:       clientKey,
			basicAuth: true,
			status:    http.StatusOK,
			authnRes:  &grpcClientsV1.AuthnRes{Id: clientID, Authenticated: true},
		},
		{
			desc:     "health check with invalid key",
			domainID: domainID,
			key:      invalidKey,
			status:   http.StatusUnauthorized,
			authnRes: &grpcClientsV1.AuthnRes{Authenticated: false},
		},
		{
			desc:      "health check with invalid basic auth",
			domainID:  domainID,
			key:       invalidKey,
			basicAuth: true,
			status:    http.StatusUnauthorized,
			authnRes:  &grpcClientsV1.AuthnRes{Authenticated: false},
		},
		{
			desc:        "health check with valid bearer token",
			domainID:    domainID,
			key:         validToken,
			bearerToken: true,
			status:      http.StatusOK,
			authnRes1:   smqauthn.Session{UserID: userID},
		},
		{
			desc:        "health check with invalid bearer token",
			domainID:    domainID,
			key:         invalidToken,
			bearerToken: true,
			status:      http.StatusUnauthorized,
			authnRes1:   smqauthn.Session{},
			authnErr:    svcerr.ErrAuthentication,
		},
		{
			desc:     "health check with empty key",
			domainID: domainID,
			key:      "",
			status:   http.StatusBadRequest,
		},
		{
			desc:     "health check with empty domain ID",
			domainID: "",
			key:      clientKey,
			status:   http.StatusBadRequest,
		},
		{
			desc:     "health check with invalid domain ID",
			domainID: invalidValue,
			key:      clientKey,
			status:   http.StatusUnauthorized,
			authnRes: &grpcClientsV1.AuthnRes{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			clientsCall := clients.On("Authenticate", mock.Anything, &grpcClientsV1.AuthnReq{Token: smqauthn.AuthPack(smqauthn.DomainAuth, tc.domainID, tc.key)}).Return(tc.authnRes, tc.authnErr)
			authCall := authn.On("Authenticate", mock.Anything, tc.key).Return(tc.authnRes1, tc.authnErr)
			domainsCall := domains.On("RetrieveIDByRoute", mock.Anything, mock.Anything).Return(&grpcCommonV1.RetrieveEntityRes{Entity: &grpcCommonV1.EntityBasic{Id: tc.domainID}}, nil)
			req := testRequest{
				client:      ts.Client(),
				method:      http.MethodPost,
				url:         fmt.Sprintf("%s/hc/%s", ts.URL, tc.domainID),
				token:       tc.key,
				basicAuth:   tc.basicAuth,
				bearerToken: tc.bearerToken,
			}
			res, err := req.make()
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
			assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))
			clientsCall.Unset()
			authCall.Unset()
			domainsCall.Unset()
		})
	}
}
