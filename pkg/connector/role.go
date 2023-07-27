package connector

import (
	"context"
	"fmt"
	"strings"

	"github.com/conductorone/baton-ldap/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grant "github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
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
		profile["role_members"] = strings.Join(members, ",")
	}

	roleTraitOptions := []rs.RoleTraitOption{
		rs.WithRoleProfile(profile),
	}

	roleName := role.GetAttributeValue(attrRoleCommonName)
	if roleName == "" {
		return nil, fmt.Errorf("ldap-connector: failed to get role name")
	}

	resource, err := rs.NewRoleResource(
		titleCaser.String(roleName),
		resourceTypeRole,
		roleName,
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

	memberIdsString, ok := rs.GetProfileStringValue(roleTrait.Profile, "role_members")
	if !ok {
		return nil, "", nil, nil
	}

	memberIds := strings.Split(memberIdsString, ",")

	// create membership grants
	var rv []*v2.Grant
	for _, id := range memberIds {
		memberEntry, _, err := r.client.LdapSearch(
			ctx,
			fmt.Sprintf("(%s=%s)", attrUserUID, id),
			nil,
			"",
			1,
		)
		if err != nil {
			return nil, "", nil, fmt.Errorf("ldap-connector: failed to get user with id %s: %w", id, err)
		}

		if len(memberEntry) == 0 {
			return nil, "", nil, fmt.Errorf("ldap-connector: failed to find user with id %s", id)
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

func roleBuilder(client *ldap.Client) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		client:       client,
	}
}
