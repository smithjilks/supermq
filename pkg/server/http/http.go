// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/absmach/supermq/pkg/server"
)

const (
	httpProtocol  = "http"
	httpsProtocol = "https"
)

type httpServer struct {
	server.BaseServer
	server    *http.Server
	tempFiles []string
}

var _ server.Server = (*httpServer)(nil)

func NewServer(ctx context.Context, cancel context.CancelFunc, name string, config server.Config, handler http.Handler, logger *slog.Logger) server.Server {
	baseServer := server.NewBaseServer(ctx, cancel, name, config, logger)
	hserver := &http.Server{Addr: baseServer.Address, Handler: handler}

	return &httpServer{
		BaseServer: baseServer,
		server:     hserver,
	}
}

func (s *httpServer) Start() error {
	errCh := make(chan error)
	s.Protocol = httpProtocol
	switch {
	case s.Config.CertFile != "" || s.Config.KeyFile != "":
		certFile, err := readFileOrData(s.Config.CertFile)
		if err != nil {
			s.cleanupTempFiles()
			return fmt.Errorf("failed to process cert file: %w", err)
		}
		if certFile != s.Config.CertFile {
			s.tempFiles = append(s.tempFiles, certFile)
		}

		keyFile, err := readFileOrData(s.Config.KeyFile)
		if err != nil {
			s.cleanupTempFiles()
			return fmt.Errorf("failed to process key file: %w", err)
		}
		if keyFile != s.Config.KeyFile {
			s.tempFiles = append(s.tempFiles, keyFile)
		}

		_, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			s.cleanupTempFiles()
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}

		s.Protocol = httpsProtocol
		s.Logger.Info(fmt.Sprintf("%s service %s server listening at %s with TLS cert %s and key %s", s.Name, s.Protocol, s.Address, s.Config.CertFile, s.Config.KeyFile))
		go func() {
			errCh <- s.server.ListenAndServeTLS(certFile, keyFile)
		}()
	default:
		s.Logger.Info(fmt.Sprintf("%s service %s server listening at %s without TLS", s.Name, s.Protocol, s.Address))
		go func() {
			errCh <- s.server.ListenAndServe()
		}()
	}
	select {
	case <-s.Ctx.Done():
		return s.Stop()
	case err := <-errCh:
		s.cleanupTempFiles()
		return err
	}
}

func (s *httpServer) Stop() error {
	defer s.Cancel()
	defer s.cleanupTempFiles()

	ctx, cancel := context.WithTimeout(context.Background(), server.StopWaitTime)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		s.Logger.Error(fmt.Sprintf("%s service %s server error occurred during shutdown at %s: %s", s.Name, s.Protocol, s.Address, err))
		return fmt.Errorf("%s service %s server error occurred during shutdown at %s: %w", s.Name, s.Protocol, s.Address, err)
	}
	s.Logger.Info(fmt.Sprintf("%s %s service shutdown of http at %s", s.Name, s.Protocol, s.Address))
	return nil
}

func (s *httpServer) cleanupTempFiles() {
	for _, tempFile := range s.tempFiles {
		if err := os.Remove(tempFile); err != nil {
			s.Logger.Error(fmt.Sprintf("Failed to remove temp file %s: %v", tempFile, err))
		}
	}
	s.tempFiles = nil
}

func readFileOrData(input string) (string, error) {
	if _, err := os.Stat(input); err == nil {
		return input, nil
	}

	tempFile, err := os.CreateTemp("", "cert-*.pem")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}

	if _, err = tempFile.WriteString(input); err != nil {
		err := os.Remove(tempFile.Name())
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("failed to write data to temp file: %w", err)
	}

	if err = tempFile.Close(); err != nil {
		err := os.Remove(tempFile.Name())
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("failed to close temp file: %w", err)
	}

	return tempFile.Name(), nil
}
