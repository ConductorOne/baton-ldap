package connector

import (
	"context"
	"errors"
	"fmt"

	"github.com/conductorone/baton-ldap/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grant "github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	ldap3 "github.com/go-ldap/ldap/v3"
)

const (
	roleFilter = "(objectClass=organizationalRole)"

	attrRoleCommonName  = "cn"
	attrRoleMember      = "roleOccupant"
	attrRoleDescription = "description"

	roleMemberEntitlement = "member"
)

type roleResourceType struct {
	resourceType *v2.ResourceType
	client       *ldap.Client
	roleSearchDN *ldap3.DN
}

func (r *roleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return r.resourceType
}

// Create a new connector resource for an LDAP Role.
func roleResource(ctx context.Context, role *ldap.Entry) (*v2.Resource, error) {
	rdn, err := ldap.CanonicalizeDN(role.DN)
	if err != nil {
		return nil, err
	}
	roleDN := rdn.String()
	profile := map[string]interface{}{
		"role_description": role.GetEqualFoldAttributeValue(attrRoleDescription),
		"path":             roleDN,
	}

	roleTraitOptions := []rs.RoleTraitOption{
		rs.WithRoleProfile(profile),
	}

	roleName := role.GetEqualFoldAttributeValue(attrRoleCommonName)
	resource, err := rs.NewRoleResource(
		roleName,
		resourceTypeRole,
		roleDN,
		roleTraitOptions,
	)
	if err != nil {
		return nil, err
	}
	return resource, nil
}

func (r *roleResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: resourceTypeRole.Id})
	if err != nil {
		return nil, "", nil, err
	}

	roleEntries, nextPage, err := r.client.LdapSearch(
		ctx,
		ldap3.ScopeWholeSubtree,
		r.roleSearchDN,
		roleFilter,
		nil,
		page,
		ResourcesPageSize,
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ldap-connector: failed to list roles: %w", err)
	}

	pageToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	var rv []*v2.Resource
	for _, roleEntry := range roleEntries {
		roleEntryCopy := roleEntry

		rr, err := roleResource(ctx, roleEntryCopy)
		if err != nil {
			return nil, "", nil, err
		}

		rv = append(rv, rr)
	}

	return rv, pageToken, nil, nil
}

func (r *roleResourceType) Entitlements(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUser),
		ent.WithDisplayName(fmt.Sprintf("%s Role %s", resource.DisplayName, roleMemberEntitlement)),
		ent.WithDescription(fmt.Sprintf("Access to %s role in LDAP", resource.DisplayName)),
	}

	// create membership entitlement
	rv = append(rv, ent.NewAssignmentEntitlement(
		resource,
		roleMemberEntitlement,
		assignmentOptions...,
	))

	return rv, "", nil, nil
}

func (r *roleResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	roleDN, err := ldap.CanonicalizeDN(resource.Id.Resource)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ldap-connector: invalid group DN: '%s' in group grants: %w", resource.Id.Resource, err)
	}
	l = l.With(zap.Stringer("role_dn", roleDN))

	ldapRole, err := r.client.LdapGet(
		ctx,
		roleDN,
		roleFilter,
		nil,
	)
	if err != nil {
		err := fmt.Errorf("ldap-connector: failed to list role members: %w", err)
		l.Error("failed to get role object", zap.Error(err))
		return nil, "", nil, err
	}

	members := parseValues(ldapRole, []string{attrRoleMember})
	var rv []*v2.Grant
	for dn := range members.Iter() {
		dnx, err := ldap.CanonicalizeDN(dn)
		if err != nil {
			return nil, "", nil, fmt.Errorf("ldap-connector: invalid DN in role_members: '%s': %w", dn, err)
		}

		urId, err := rs.NewResourceID(resourceTypeUser, dnx.String())
		if err != nil {
			return nil, "", nil, fmt.Errorf("ldap-connector: failed to find user with dn %s", dn)
		}
		rv = append(
			rv,
			grant.NewGrant(
				resource,
				roleMemberEntitlement,
				urId,
			),
		)
	}

	return rv, "", nil, nil
}

func (r *roleResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	if principal.Id.ResourceType != resourceTypeUser.Id {
		return nil, fmt.Errorf("baton-ldap: only users can have role membership granted")
	}

	roleDN := entitlement.Resource.Id.Resource

	principalDNArr := []string{principal.Id.Resource}
	modifyRequest := ldap3.NewModifyRequest(roleDN, nil)
	modifyRequest.Add(attrRoleMember, principalDNArr)

	// grant role memberships to the principal
	err := r.client.LdapModify(
		ctx,
		modifyRequest,
	)
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: failed to grant role membership to user: %w", err)
	}

	return nil, nil
}

func (r *roleResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	entitlement := grant.Entitlement
	principal := grant.Principal

	if principal.Id.ResourceType != resourceTypeUser.Id {
		return nil, fmt.Errorf("baton-ldap: only users can have role membership revoked")
	}

	roleDN := entitlement.Resource.Id.Resource

	principalDNArr := []string{principal.Id.Resource}
	modifyRequest := ldap3.NewModifyRequest(roleDN, nil)
	modifyRequest.Delete(attrRoleMember, principalDNArr)

	// revoke role memberships from the principal
	err := r.client.LdapModify(
		ctx,
		modifyRequest,
	)
	if err != nil {
		var lerr *ldap3.Error
		if errors.As(err, &lerr) {
			if lerr.ResultCode == ldap3.LDAPResultNoSuchAttribute {
				return nil, nil
			}
		}
		return nil, fmt.Errorf("ldap-connector: failed to revoke role membership from user: %w", err)
	}

	return nil, nil
}

func roleBuilder(client *ldap.Client, roleSearchDN *ldap3.DN) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		client:       client,
		roleSearchDN: roleSearchDN,
	}
}
