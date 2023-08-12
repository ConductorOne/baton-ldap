package connector

import (
	"context"
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
}

func (r *roleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return r.resourceType
}

// Create a new connector resource for an LDAP Role.
func roleResource(ctx context.Context, role *ldap.Entry) (*v2.Resource, error) {
	members, err := parseMembers(role, attrRoleMember)
	if err != nil {
		return nil, err
	}

	profile := map[string]interface{}{
		"role_description": role.GetAttributeValue(attrRoleDescription),
	}

	if len(members) > 0 {
		profile["role_members"] = StringSliceToInterfaceSlice(members)
	}

	roleTraitOptions := []rs.RoleTraitOption{
		rs.WithRoleProfile(profile),
	}

	roleName := role.GetAttributeValue(attrRoleCommonName)
	resource, err := rs.NewRoleResource(
		titleCaser.String(roleName),
		resourceTypeRole,
		role.DN,
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
		roleFilter,
		nil,
		page,
		uint32(ResourcesPageSize),
		"",
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
	roleTrait, err := rs.GetRoleTrait(resource)
	if err != nil {
		return nil, "", nil, err
	}

	memberDNStrings, ok := GetProfileStringArray(roleTrait.Profile, "role_members")
	if !ok {
		return nil, "", nil, nil
	}

	// create membership grants
	var rv []*v2.Grant
	for _, dn := range memberDNStrings {
		memberEntry, _, err := r.client.LdapSearch(
			ctx,
			"",
			nil,
			"",
			1,
			dn,
		)
		if err != nil {
			return nil, "", nil, fmt.Errorf("ldap-connector: failed to get user with dn %s: %w", dn, err)
		}

		if len(memberEntry) == 0 {
			return nil, "", nil, fmt.Errorf("ldap-connector: failed to find user with dn %s", dn)
		}

		memberCopy := memberEntry
		ur, err := userResource(ctx, memberCopy[0])
		if err != nil {
			return nil, "", nil, err
		}

		rv = append(
			rv,
			grant.NewGrant(
				resource,
				roleMemberEntitlement,
				ur.Id,
			),
		)
	}

	return rv, "", nil, nil
}

func (r *roleResourceType) findRoleMembers(ctx context.Context, role string) (string, []string, error) {
	roleEntry, _, err := r.client.LdapSearch(
		ctx,
		"",
		nil,
		"",
		1,
		role,
	)
	if err != nil {
		return "", nil, fmt.Errorf("ldap-connector: failed to get role %s: %w", role, err)
	}

	if len(roleEntry) == 0 {
		return "", nil, fmt.Errorf("ldap-connector: failed to get role %s", role)
	}

	membersPayload := roleEntry[0].GetAttributeValues(attrRoleMember)

	return roleEntry[0].DN, membersPayload, nil
}

func (r *roleResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"baton-ldap: only users can have role membership granted",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)

		return nil, nil
	}

	roleId := entitlement.Resource.Id.Resource

	// get all current members of the role
	roleDN, memberEntries, err := r.findRoleMembers(ctx, roleId)
	if err != nil {
		return nil, err
	}

	// check if principal is a member of the role
	if containsMember(memberEntries, principal.Id.Resource) {
		// the user is already a member of the role, so do nothing.
		return nil, nil
	}

	// This checks to see if the user exists in LDAP.
	// TODO: We could probably skip this step, since we already have the principal
	_, err = r.client.CreateMemberEntry(ctx, principal.Id.Resource)
	if err != nil {
		return nil, err
	}

	updatedEntries := addMember(memberEntries, principal.Id.Resource)

	// grant role memberships to the principal
	err = r.client.LdapModify(
		ctx,
		roleDN,
		attrRoleMember,
		updatedEntries,
	)
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: failed to grant role membership to user: %w", err)
	}

	return nil, nil
}

func (r *roleResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	entitlement := grant.Entitlement
	principal := grant.Principal

	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"baton-ldap: only users can have role membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
	}

	roleId := entitlement.Resource.Id.Resource

	// get all current members of the role
	roleDN, memberEntries, err := r.findRoleMembers(ctx, roleId)
	if err != nil {
		return nil, err
	}

	// check if principal is a member of the role
	if !containsMember(memberEntries, principal.Id.Resource) {
		// the user is already not a member of the role, so do nothing.
		return nil, nil
	}

	// remove principal from members
	updatedEntries, err := removeMember(memberEntries, principal.Id.Resource)
	if err != nil {
		return nil, err
	}

	// revoke role memberships from the principal
	err = r.client.LdapModify(
		ctx,
		roleDN,
		attrRoleMember,
		updatedEntries,
	)
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: failed to revoke role membership from user: %w", err)
	}

	return nil, nil
}

func roleBuilder(client *ldap.Client) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		client:       client,
	}
}
