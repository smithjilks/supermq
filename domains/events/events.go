// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"time"

	"github.com/absmach/supermq/domains"
	"github.com/absmach/supermq/pkg/authn"
	"github.com/absmach/supermq/pkg/events"
	"github.com/absmach/supermq/pkg/roles"
)

const (
	domainPrefix         = "domain."
	domainCreate         = domainPrefix + "create"
	domainRetrieve       = domainPrefix + "retrieve"
	domainRetrieveStatus = domainPrefix + "retrieve_status"
	domainUpdate         = domainPrefix + "update"
	domainEnable         = domainPrefix + "enable"
	domainDisable        = domainPrefix + "disable"
	domainFreeze         = domainPrefix + "freeze"
	domainList           = domainPrefix + "list"
	domainUserDelete     = domainPrefix + "user_delete"
	invitationPrefix     = "invitation."
	invitationSend       = invitationPrefix + "send"
	invitationAccept     = invitationPrefix + "accept"
	invitationReject     = invitationPrefix + "reject"
	invitationList       = invitationPrefix + "list"
	invitationRetrieve   = invitationPrefix + "retrieve"
	invitationDelete     = invitationPrefix + "delete"
)

var (
	_ events.Event = (*createDomainEvent)(nil)
	_ events.Event = (*retrieveDomainEvent)(nil)
	_ events.Event = (*retrieveDomainStatusEvent)(nil)
	_ events.Event = (*updateDomainEvent)(nil)
	_ events.Event = (*enableDomainEvent)(nil)
	_ events.Event = (*disableDomainEvent)(nil)
	_ events.Event = (*freezeDomainEvent)(nil)
	_ events.Event = (*listDomainsEvent)(nil)
	_ events.Event = (*sendInvitationEvent)(nil)
	_ events.Event = (*viewInvitationEvent)(nil)
	_ events.Event = (*listInvitationsEvent)(nil)
	_ events.Event = (*acceptInvitationEvent)(nil)
	_ events.Event = (*rejectInvitationEvent)(nil)
	_ events.Event = (*deleteInvitationEvent)(nil)
)

type createDomainEvent struct {
	domains.Domain
	rolesProvisioned []roles.RoleProvision
	authn.Session
}

func (cde createDomainEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":         domainCreate,
		"id":                cde.ID,
		"alias":             cde.Alias,
		"status":            cde.Status.String(),
		"created_at":        cde.CreatedAt,
		"created_by":        cde.CreatedBy,
		"roles_provisioned": cde.rolesProvisioned,
		"user_id":           cde.UserID,
		"token_type":        cde.Type.String(),
		"super_admin":       cde.SuperAdmin,
	}

	if cde.Name != "" {
		val["name"] = cde.Name
	}
	if len(cde.Tags) > 0 {
		val["tags"] = cde.Tags
	}
	if cde.Metadata != nil {
		val["metadata"] = cde.Metadata
	}

	return val, nil
}

type retrieveDomainEvent struct {
	domains.Domain
	authn.Session
}

func (rde retrieveDomainEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":   domainRetrieve,
		"id":          rde.ID,
		"alias":       rde.Alias,
		"status":      rde.Status.String(),
		"created_at":  rde.CreatedAt,
		"user_id":     rde.UserID,
		"token_type":  rde.Type.String(),
		"super_admin": rde.SuperAdmin,
	}

	if rde.Name != "" {
		val["name"] = rde.Name
	}
	if len(rde.Tags) > 0 {
		val["tags"] = rde.Tags
	}
	if rde.Metadata != nil {
		val["metadata"] = rde.Metadata
	}

	if !rde.UpdatedAt.IsZero() {
		val["updated_at"] = rde.UpdatedAt
	}
	if rde.UpdatedBy != "" {
		val["updated_by"] = rde.UpdatedBy
	}
	return val, nil
}

type retrieveDomainStatusEvent struct {
	id     string
	status domains.Status
	authn.Session
}

func (rdse retrieveDomainStatusEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":   domainRetrieve,
		"id":          rdse.id,
		"status":      rdse.status.String(),
		"user_id":     rdse.UserID,
		"token_type":  rdse.Type.String(),
		"super_admin": rdse.SuperAdmin,
	}

	return val, nil
}

type updateDomainEvent struct {
	domains.Domain
	authn.Session
}

func (ude updateDomainEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":   domainUpdate,
		"id":          ude.ID,
		"alias":       ude.Alias,
		"status":      ude.Status.String(),
		"created_at":  ude.CreatedAt,
		"created_by":  ude.CreatedBy,
		"updated_at":  ude.UpdatedAt,
		"updated_by":  ude.UpdatedBy,
		"user_id":     ude.UserID,
		"token_type":  ude.Type.String(),
		"super_admin": ude.SuperAdmin,
	}

	if ude.Name != "" {
		val["name"] = ude.Name
	}
	if len(ude.Tags) > 0 {
		val["tags"] = ude.Tags
	}
	if ude.Metadata != nil {
		val["metadata"] = ude.Metadata
	}

	return val, nil
}

type enableDomainEvent struct {
	domainID  string
	updatedAt time.Time
	updatedBy string
	authn.Session
}

func (cdse enableDomainEvent) Encode() (map[string]interface{}, error) {
	return map[string]interface{}{
		"operation":   domainEnable,
		"id":          cdse.domainID,
		"updated_at":  cdse.updatedAt,
		"updated_by":  cdse.updatedBy,
		"user_id":     cdse.UserID,
		"token_type":  cdse.Type.String(),
		"super_admin": cdse.SuperAdmin,
	}, nil
}

type disableDomainEvent struct {
	domainID  string
	updatedAt time.Time
	updatedBy string
	authn.Session
}

func (cdse disableDomainEvent) Encode() (map[string]interface{}, error) {
	return map[string]interface{}{
		"operation":   domainDisable,
		"id":          cdse.domainID,
		"updated_at":  cdse.updatedAt,
		"updated_by":  cdse.updatedBy,
		"user_id":     cdse.UserID,
		"token_type":  cdse.Type.String(),
		"super_admin": cdse.SuperAdmin,
	}, nil
}

type freezeDomainEvent struct {
	domainID  string
	updatedAt time.Time
	updatedBy string
	authn.Session
}

func (cdse freezeDomainEvent) Encode() (map[string]interface{}, error) {
	return map[string]interface{}{
		"operation":   domainFreeze,
		"id":          cdse.domainID,
		"updated_at":  cdse.updatedAt,
		"updated_by":  cdse.updatedBy,
		"user_id":     cdse.UserID,
		"token_type":  cdse.Type.String(),
		"super_admin": cdse.SuperAdmin,
	}, nil
}

type listDomainsEvent struct {
	domains.Page
	total      uint64
	userID     string
	tokenType  string
	superAdmin bool
}

func (lde listDomainsEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":   domainList,
		"total":       lde.total,
		"offset":      lde.Offset,
		"limit":       lde.Limit,
		"user_id":     lde.userID,
		"token_type":  lde.tokenType,
		"super_admin": lde.superAdmin,
	}

	if lde.Name != "" {
		val["name"] = lde.Name
	}
	if lde.Order != "" {
		val["order"] = lde.Order
	}
	if lde.Dir != "" {
		val["dir"] = lde.Dir
	}
	if lde.Metadata != nil {
		val["metadata"] = lde.Metadata
	}
	if lde.Tag != "" {
		val["tag"] = lde.Tag
	}
	if lde.RoleID != "" {
		val["role_id"] = lde.RoleID
	}
	if lde.RoleName != "" {
		val["role_name"] = lde.RoleName
	}
	if len(lde.Actions) != 0 {
		val["actions"] = lde.Actions
	}
	if lde.Status.String() != "" {
		val["status"] = lde.Status.String()
	}
	if lde.ID != "" {
		val["id"] = lde.ID
	}
	if len(lde.IDs) > 0 {
		val["ids"] = lde.IDs
	}
	if lde.Identity != "" {
		val["identity"] = lde.Identity
	}
	if lde.UserID != "" {
		val["user_id"] = lde.UserID
	}

	return val, nil
}

type sendInvitationEvent struct {
	invitation domains.Invitation
	session    authn.Session
}

func (sie sendInvitationEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":       invitationSend,
		"invitee_user_id": sie.invitation.InviteeUserID,
		"domain_id":       sie.invitation.DomainID,
		"invited_by":      sie.session.UserID,
		"role_id":         sie.invitation.RoleID,
		"token_type":      sie.session.Type.String(),
		"super_admin":     sie.session.SuperAdmin,
	}

	return val, nil
}

type viewInvitationEvent struct {
	inviteeUserID string
	domainID      string
	roleID        string
	roleName      string
	session       authn.Session
}

func (vie viewInvitationEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":       invitationRetrieve,
		"invitee_user_id": vie.inviteeUserID,
		"domain_id":       vie.domainID,
		"role_id":         vie.roleID,
		"role_name":       vie.roleName,
		"token_type":      vie.session.Type.String(),
		"super_admin":     vie.session.SuperAdmin,
	}

	return val, nil
}

type listInvitationsEvent struct {
	domains.InvitationPageMeta
	session authn.Session
}

func (lie listInvitationsEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":   invitationList,
		"offset":      lie.Offset,
		"limit":       lie.Limit,
		"user_id":     lie.session.UserID,
		"token_type":  lie.session.Type.String(),
		"super_admin": lie.session.SuperAdmin,
	}

	if lie.InvitedBy != "" {
		val["invited_by"] = lie.InvitedBy
	}
	if lie.InviteeUserID != "" {
		val["invitee_user_id"] = lie.InviteeUserID
	}
	if lie.DomainID != "" {
		val["domain_id"] = lie.DomainID
	}
	if lie.RoleID != "" {
		val["role_id"] = lie.RoleID
	}
	if lie.State.String() != "" {
		val["state"] = lie.State.String()
	}

	return val, nil
}

type acceptInvitationEvent struct {
	domainID string
	session  authn.Session
}

func (aie acceptInvitationEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":       invitationAccept,
		"domain_id":       aie.domainID,
		"invitee_user_id": aie.session.UserID,
		"token_type":      aie.session.Type.String(),
		"super_admin":     aie.session.SuperAdmin,
	}

	return val, nil
}

type rejectInvitationEvent struct {
	domainID string
	session  authn.Session
}

func (rie rejectInvitationEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":       invitationReject,
		"domain_id":       rie.domainID,
		"invitee_user_id": rie.session.UserID,
		"token_type":      rie.session.Type.String(),
		"super_admin":     rie.session.SuperAdmin,
	}

	return val, nil
}

type deleteInvitationEvent struct {
	inviteeUserID string
	domainID      string
	session       authn.Session
}

func (die deleteInvitationEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":       invitationDelete,
		"invitee_user_id": die.inviteeUserID,
		"domain_id":       die.domainID,
		"token_type":      die.session.Type.String(),
		"super_admin":     die.session.SuperAdmin,
	}

	return val, nil
}
