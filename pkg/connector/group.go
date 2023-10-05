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
	ldap3 "github.com/go-ldap/ldap/v3"
)

const (
	groupFilter = "(|(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"

	attrGroupCommonName  = "cn"
	attrGroupIdPosix     = "gidNumber"
	attrGroupMember      = "uniqueMember"
	attrGroupMemberPosix = "memberUid"
	attrGroupDescription = "description"

	groupMemberEntitlement = "member"
)

type groupResourceType struct {
	resourceType *v2.ResourceType
	client       *ldap.Client
}

func (g *groupResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return g.resourceType
}

// Create a new connector resource for an LDAP Group.
func groupResource(ctx context.Context, group *ldap.Entry) (*v2.Resource, error) {
	groupId := parseValue(group, []string{attrGroupIdPosix})
	members := parseValues(group, []string{attrGroupMember, attrGroupMemberPosix})
	profile := map[string]interface{}{
		"group_description": group.GetAttributeValue(attrGroupDescription),
	}

	if groupId != "" {
		profile["group_id"] = groupId
	}

	if len(members) > 0 {
		profile["group_members"] = stringSliceToInterfaceSlice(members)
	}

	groupTraitOptions := []rs.GroupTraitOption{
		rs.WithGroupProfile(profile),
	}

	groupName := group.GetAttributeValue(attrGroupCommonName)

	resource, err := rs.NewGroupResource(
		titleCaser.String(groupName),
		resourceTypeGroup,
		group.DN,
		groupTraitOptions,
	)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func (g *groupResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: resourceTypeGroup.Id})
	if err != nil {
		return nil, "", nil, err
	}

	groupEntries, nextPage, err := g.client.LdapSearch(
		ctx,
		groupFilter,
		nil,
		page,
		uint32(ResourcesPageSize),
		"",
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ldap-connector: failed to list groups: %w", err)
	}

	pageToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	var rv []*v2.Resource
	for _, groupEntry := range groupEntries {
		groupEntryCopy := groupEntry

		gr, err := groupResource(ctx, groupEntryCopy)
		if err != nil {
			return nil, "", nil, err
		}

		rv = append(rv, gr)
	}

	return rv, pageToken, nil, nil
}

func (g *groupResourceType) Entitlements(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUser),
		ent.WithDisplayName(fmt.Sprintf("%s Group %s", resource.DisplayName, groupMemberEntitlement)),
		ent.WithDescription(fmt.Sprintf("Access to %s group in LDAP", resource.DisplayName)),
	}

	// create membership entitlement
	rv = append(rv, ent.NewAssignmentEntitlement(
		resource,
		groupMemberEntitlement,
		assignmentOptions...,
	))

	return rv, "", nil, nil
}

func (g *groupResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	groupTrait, err := rs.GetGroupTrait(resource)
	if err != nil {
		return nil, "", nil, err
	}

	memberDNStrings, ok := getProfileStringArray(groupTrait.Profile, "group_members")
	if !ok {
		return nil, "", nil, nil
	}

	// create membership grants
	var rv []*v2.Grant
	for _, dn := range memberDNStrings {
		memberEntry, _, err := g.client.LdapSearch(
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
				groupMemberEntitlement,
				ur.Id,
			),
		)
	}

	return rv, "", nil, nil
}

func (g *groupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	if principal.Id.ResourceType != resourceTypeUser.Id {
		return nil, fmt.Errorf("baton-ldap: only users can have group membership granted")
	}

	groupDN := entitlement.Resource.Id.Resource

	// This checks to see if the user exists in LDAP.
	// TODO: We could probably skip this step, since we already have the principal
	_, err := g.client.CreateMemberEntry(ctx, principal.Id.Resource)
	if err != nil {
		return nil, err
	}

	principalDNArr := []string{principal.Id.Resource}
	modifyRequest := ldap3.NewModifyRequest(groupDN, nil)
	modifyRequest.Add(attrGroupMember, principalDNArr)

	// grant group membership to the principal
	err = g.client.LdapModify(
		ctx,
		modifyRequest,
	)
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: failed to grant group membership to user: %w", err)
	}

	return nil, nil
}

func (g *groupResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	entitlement := grant.Entitlement
	principal := grant.Principal

	if principal.Id.ResourceType != resourceTypeUser.Id {
		return nil, fmt.Errorf("baton-ldap: only users can have group membership revoked")
	}

	groupDN := entitlement.Resource.Id.Resource

	principalDNArr := []string{principal.Id.Resource}
	modifyRequest := ldap3.NewModifyRequest(groupDN, nil)
	modifyRequest.Delete(attrGroupMember, principalDNArr)

	// revoke group membership from the principal
	err := g.client.LdapModify(
		ctx,
		modifyRequest,
	)
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: failed to revoke group membership from user: %w", err)
	}

	return nil, nil
}

func groupBuilder(client *ldap.Client) *groupResourceType {
	return &groupResourceType{
		resourceType: resourceTypeGroup,
		client:       client,
	}
}
