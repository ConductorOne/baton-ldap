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
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	groupFilter = "(objectClass=groupOfUniqueNames)"

	attrGroupCommonName  = "cn"
	attrGroupMember      = "uniqueMember"
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
	members, err := parseMembers(group, attrGroupMember)
	if err != nil {
		return nil, err
	}

	profile := map[string]interface{}{
		"group_description": group.GetAttributeValue(attrGroupDescription),
	}

	if len(members) > 0 {
		profile["group_members"] = strings.Join(members, ",")
	}

	groupTraitOptions := []rs.GroupTraitOption{
		rs.WithGroupProfile(profile),
	}

	groupName := group.GetAttributeValue(attrGroupCommonName)
	if groupName == "" {
		return nil, fmt.Errorf("ldap-connector: failed to get group name")
	}

	resource, err := rs.NewGroupResource(
		titleCaser.String(groupName),
		resourceTypeGroup,
		groupName,
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

	memberIdsString, ok := rs.GetProfileStringValue(groupTrait.Profile, "group_members")
	if !ok {
		return nil, "", nil, nil
	}

	memberIds := strings.Split(memberIdsString, ",")

	// create membership grants
	var rv []*v2.Grant
	for _, id := range memberIds {
		memberEntry, _, err := g.client.LdapSearch(
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
				groupMemberEntitlement,
				ur.Id,
			),
		)
	}

	return rv, "", nil, nil
}

func (g *groupResourceType) findGroupMembers(ctx context.Context, group string) (string, []string, error) {
	groupEntry, _, err := g.client.LdapSearch(
		ctx,
		fmt.Sprintf("(%s=%s)", attrGroupCommonName, group),
		nil,
		"",
		1,
	)
	if err != nil {
		return "", nil, fmt.Errorf("ldap-connector: failed to get group %s: %w", group, err)
	}

	if len(groupEntry) == 0 {
		return "", nil, fmt.Errorf("ldap-connector: failed to get group %s", group)
	}

	membersPayload := groupEntry[0].GetAttributeValues(attrGroupMember)

	return groupEntry[0].DN, membersPayload, nil
}

func (g *groupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"baton-ldap: only users can have group membership granted",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)

		return nil, nil
	}

	groupId, err := extractResourceId(entitlement.Id)
	if err != nil {
		return nil, err
	}

	// get all current members of the group
	groupDN, memberEntries, err := g.findGroupMembers(ctx, groupId)
	if err != nil {
		return nil, err
	}

	// check if user is already a member of the group
	if containsMember(memberEntries, principal.Id.Resource) {
		l.Warn(
			"baton-ldap: cannot add user who already is a member of the group",
			zap.String("group", entitlement.Id),
			zap.String("user", principal.Id.Resource),
		)

		return nil, fmt.Errorf("ldap-connector: cannot add user who already is a member of the group")
	}

	principalEntry, err := g.client.CreateMemberEntry(principal.Id.Resource, memberEntries[0])
	if err != nil {
		return nil, err
	}

	updatedEntries := addMember(memberEntries, principalEntry)

	// grant group membership to the principal
	err = g.client.LdapModify(
		ctx,
		groupDN,
		attrGroupMember,
		updatedEntries,
	)
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: failed to grant group membership to user: %w", err)
	}

	return nil, nil
}

func (g *groupResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	entitlement := grant.Entitlement
	principal := grant.Principal

	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"baton-ldap: only users can have group membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
	}

	groupId, err := extractResourceId(entitlement.Id)
	if err != nil {
		return nil, err
	}

	// get all current members of the group
	groupDN, memberEntries, err := g.findGroupMembers(ctx, groupId)
	if err != nil {
		return nil, err
	}

	// check if principal is a member of the group
	if !containsMember(memberEntries, principal.Id.Resource) {
		l.Warn(
			"baton-ldap: cannot remove user from group they are not a member of",
			zap.String("group", entitlement.Id),
			zap.String("user", principal.Id.Resource),
		)

		return nil, fmt.Errorf("ldap-connector: cannot remove user from group they are not a member of")
	}

	// remove principal from members
	updatedEntries, err := removeMember(memberEntries, principal.Id.Resource)
	if err != nil {
		return nil, err
	}

	// revoke group membership from the principal
	err = g.client.LdapModify(
		ctx,
		groupDN,
		attrGroupMember,
		updatedEntries,
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
