package connector

import (
	"context"
	"fmt"
	"slices"

	"github.com/conductorone/baton-ldap/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grant "github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	ldap3 "github.com/go-ldap/ldap/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	groupFilter       = "(|(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"
	groupIdFilter     = "(&(gidNumber=%s)(|(objectClass=groupOfUniqueNames)(objectClass=posixGroup)))"
	groupMemberFilter = "(&(objectClass=posixAccount)(uid=%s))"

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
	// Don't save members in profile since that could be a ton of data, wasting storage and hitting GRPC limits
	profile := map[string]interface{}{
		"group_description": group.GetAttributeValue(attrGroupDescription),
	}

	if groupId != "" {
		profile["gid"] = groupId
	}

	groupTraitOptions := []rs.GroupTraitOption{
		rs.WithGroupProfile(profile),
	}

	groupName := group.GetAttributeValue(attrGroupCommonName)

	resource, err := rs.NewGroupResource(
		groupName,
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
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeGroup.Id})
	if err != nil {
		return nil, "", nil, err
	}

	// TODO: fetch by cn instead of gid?
	v, ok := groupTrait.Profile.Fields["gid"]
	if !ok {
		return nil, "", nil, fmt.Errorf("ldap-connector: no group id")
	}
	s, ok := v.Kind.(*structpb.Value_StringValue)
	if !ok {
		return nil, "", nil, fmt.Errorf("ldap-connector: group id isn't a string")
	}
	groupId := s.StringValue

	query := fmt.Sprintf(groupIdFilter, groupId)
	ldapGroup, nextPage, err := g.client.LdapSearch(
		ctx,
		query,
		nil,
		page,
		uint32(ResourcesPageSize),
		"",
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ldap-connector: failed to list group members: %w", err)
	}
	if len(ldapGroup) == 0 {
		return nil, "", nil, fmt.Errorf("ldap-connector: no group found")
	}
	if len(ldapGroup) > 1 {
		return nil, "", nil, fmt.Errorf("ldap-connector: too many groups found")
	}

	pageToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	memberIds := parseValues(ldapGroup[0], []string{attrGroupMember, attrGroupMemberPosix})
	if len(memberIds) == 0 {
		return nil, "", nil, fmt.Errorf("ldap-connector: no members found")
	}

	// create membership grants
	var rv []*v2.Grant
	for _, memberId := range memberIds {
		var memberEntry []*ldap.Entry

		if parsedDN, err := ldap3.ParseDN(memberId); err == nil {
			memberEntry, _, err = g.client.LdapSearch(
				ctx,
				"",
				nil,
				"",
				1,
				parsedDN.String(),
			)
			if err != nil {
				return nil, pageToken, nil, fmt.Errorf("ldap-connector: failed to get user with dn %s: %w", memberId, err)
			}
		} else {
			// Group member doesn't look like it is a DN, search for it as a UID
			memberEntry, _, err = g.client.LdapSearch(
				ctx,
				fmt.Sprintf(groupMemberFilter, memberId),
				nil,
				"",
				1,
				"",
			)
			if err != nil {
				return nil, pageToken, nil, fmt.Errorf("ldap-connector: failed to get user with uid %s: %w", memberId, err)
			}
		}

		if len(memberEntry) == 0 {
			return nil, pageToken, nil, fmt.Errorf("ldap-connector: failed to find user with dn or UID %s", memberId)
		}

		for _, e := range memberEntry {
			g := grant.NewGrant(
				// remove group profile from grant so we're not saving all group memberships in every grant
				&v2.Resource{
					Id: resource.Id,
				},
				groupMemberEntitlement,
				// remove user profile from grant so we're not saving repetitive user info in every grant
				&v2.ResourceId{
					ResourceType: resourceTypeUser.Id,
					Resource:     e.DN,
				},
			)

			rv = append(rv, g)
		}
	}

	return rv, pageToken, nil, nil
}

func (g *groupResourceType) getGroup(ctx context.Context, groupDN string) (*ldap3.Entry, error) {
	groupEntries, _, err := g.client.LdapSearch(
		ctx,
		groupFilter,
		nil,
		"",
		uint32(ResourcesPageSize),
		groupDN,
	)
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: failed to get group: %w", err)
	}

	if len(groupEntries) == 0 {
		return nil, fmt.Errorf("ldap-connector: group DN %s not found", groupDN)
	}

	return groupEntries[0], nil
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

	modifyRequest := ldap3.NewModifyRequest(groupDN, nil)

	group, err := g.getGroup(ctx, groupDN)
	if err != nil {
		return nil, err
	}

	if slices.Contains(group.GetAttributeValues("objectClass"), "posixGroup") {
		dn, err := ldap3.ParseDN(principal.Id.Resource)
		if err != nil {
			return nil, err
		}
		username := []string{dn.RDNs[0].Attributes[0].Value}
		modifyRequest.Add(attrGroupMemberPosix, username)
	} else {
		principalDNArr := []string{principal.Id.Resource}
		modifyRequest.Add(attrGroupMember, principalDNArr)
	}

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

	modifyRequest := ldap3.NewModifyRequest(groupDN, nil)

	group, err := g.getGroup(ctx, groupDN)
	if err != nil {
		return nil, err
	}

	if slices.Contains(group.GetAttributeValues("objectClass"), "posixGroup") {
		dn, err := ldap3.ParseDN(principal.Id.Resource)
		if err != nil {
			return nil, err
		}
		username := []string{dn.RDNs[0].Attributes[0].Value}
		modifyRequest.Delete(attrGroupMemberPosix, username)
	} else {
		principalDNArr := []string{principal.Id.Resource}
		modifyRequest.Delete(attrGroupMember, principalDNArr)
	}

	// revoke group membership from the principal
	err = g.client.LdapModify(
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
