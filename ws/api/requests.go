// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

type connReq struct {
	authKey   string
	channelID string
	domainID  string
	subtopic  string
}
