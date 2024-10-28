package connector

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/conductorone/baton-ldap/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grant "github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
)

const (
	groupObjectClasses = "(objectClass=groupOfUniqueNames)(objectClass=posixGroup)(objectClass=group)"
	groupFilter        = "(|" + groupObjectClasses + ")"
	groupIdFilter      = "(&(gidNumber=%s)(|" + groupObjectClasses + "))"

	groupMemberUIDFilter        = `(&` + userFilter + `(uid=%s))`
	groupMemberCommonNameFilter = `(&` + userFilter + `(cn=%s))`

	groupMemberGidNumber = `(&` + userFilter + `(gidNumber=%s))`

	attrGroupCommonName   = "cn"
	attrGroupIdPosix      = "gidNumber"
	attrGroupMember       = "member"
	attrGroupUniqueMember = "uniqueMember"
	attrGroupMemberPosix  = "memberUid"
	attrGroupDescription  = "description"

	groupMemberEntitlement = "member"
)

type groupResourceType struct {
	resourceType  *v2.ResourceType
	groupSearchDN *ldap3.DN
	userSearchDN  *ldap3.DN
	client        *ldap.Client

	uid2dnCache map[string]string
	uid2dnMtx   sync.Mutex
}

func (g *groupResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return g.resourceType
}

// Create a new connector resource for an LDAP Group.
func groupResource(ctx context.Context, group *ldap.Entry) (*v2.Resource, error) {
	gdn, err := ldap.CanonicalizeDN(group.DN)
	if err != nil {
		return nil, err
	}
	groupDN := gdn.String()
	groupId := parseValue(group, []string{attrGroupIdPosix})
	profile := map[string]interface{}{
		"group_description": group.GetEqualFoldAttributeValue(attrGroupDescription),
		"path":              groupDN,
	}

	if groupId != "" {
		profile["gid"] = groupId
	}

	groupTraitOptions := []rs.GroupTraitOption{
		rs.WithGroupProfile(profile),
	}

	groupName := group.GetEqualFoldAttributeValue(attrGroupCommonName)

	resource, err := rs.NewGroupResource(
		groupName,
		resourceTypeGroup,
		groupDN,
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
		ldap3.ScopeWholeSubtree,
		g.groupSearchDN,
		groupFilter,
		nil,
		page,
		ResourcesPageSize,
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ldap-connector: failed to list groups in '%s': %w", g.groupSearchDN.String(), err)
	}

	pageToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	var rv []*v2.Resource
	for _, groupEntry := range groupEntries {
		gr, err := groupResource(ctx, groupEntry)
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

// newGrantFromDN - create a `Grant` from a given group and user distinguished name.
func newGrantFromDN(resource *v2.Resource, userDN string) *v2.Grant {
	g := grant.NewGrant(
		// remove group profile from grant so we're not saving all group memberships in every grant
		&v2.Resource{
			Id: resource.Id,
		},
		groupMemberEntitlement,
		// remove user profile from grant so we're not saving repetitive user info in every grant
		&v2.ResourceId{
			ResourceType: resourceTypeUser.Id,
			Resource:     userDN,
		},
	)
	return g
}

func (g *groupResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	groupDN, err := ldap.CanonicalizeDN(resource.Id.Resource)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ldap-connector: invalid group DN: '%s' in group grants: %w", resource.Id.Resource, err)
	}
	l = l.With(zap.Stringer("group_dn", groupDN))

	ldapGroup, err := g.client.LdapGet(
		ctx,
		groupDN,
		groupFilter,
		nil,
	)
	if err != nil {
		l.Error("ldap-connector: failed to list group members", zap.String("group_dn", resource.Id.Resource), zap.Error(err))

		// Some LDAP servers lie.
		if ldap3.IsErrorAnyOf(err, ldap3.LDAPResultNoSuchObject) {
			return nil, "", nil, nil
		}

		err := fmt.Errorf("ldap-connector: failed to list group %s members: %w", resource.Id.Resource, err)
		return nil, "", nil, err
	}

	memberIDs := parseValues(ldapGroup, []string{attrGroupUniqueMember, attrGroupMember, attrGroupMemberPosix})

	// create membership grants
	var rv []*v2.Grant
	for memberId := range memberIDs.Iter() {
		parsedDN, err := ldap.CanonicalizeDN(memberId)
		if err == nil {
			g := newGrantFromDN(resource, parsedDN.String())
			rv = append(rv, g)
			continue
		}

		memberDN, err := g.findMember(ctx, memberId)
		if err != nil {
			return nil, "", nil, err
		}
		if memberDN == "" {
			continue
		}
		g := newGrantFromDN(resource, memberDN)
		rv = append(rv, g)
	}

	posixGid := ldapGroup.GetEqualFoldAttributeValue(attrGroupIdPosix)
	if posixGid == "" {
		return rv, "", nil, nil
	}

	nextPage := ""
	for {
		var userEntries []*ldap3.Entry
		userEntries, nextPage, err = g.client.LdapSearch(
			ctx,
			ldap3.ScopeWholeSubtree,
			g.userSearchDN,
			fmt.Sprintf(groupMemberGidNumber, ldap3.EscapeFilter(posixGid)),
			[]string{"dn"},
			nextPage, 100,
		)
		if err != nil {
			return nil, "", nil, fmt.Errorf("ldap-connector: failed to list group members: %w", err)
		}
		for _, userEntry := range userEntries {
			userDN, err := ldap.CanonicalizeDN(userEntry.DN)
			if err != nil {
				l.Error("ldap-connector: invalid user DN", zap.String("user_dn", userEntry.DN), zap.Error(err))
				continue
			}
			g := newGrantFromDN(resource, userDN.String())
			rv = append(rv, g)
		}
		if nextPage == "" {
			break
		}
	}

	rv = uniqueGrants(rv)

	return rv, "", nil, nil
}

func uniqueGrants(grants []*v2.Grant) []*v2.Grant {
	seen := make(map[string]struct{})
	var uniqueGrants []*v2.Grant
	for _, grant := range grants {
		if _, ok := seen[grant.Principal.Id.Resource]; !ok {
			uniqueGrants = append(uniqueGrants, grant)
			seen[grant.Principal.Id.Resource] = struct{}{}
		}
	}
	return uniqueGrants
}

// findMember: note this function can return an empty string if the member is not found.
func (g *groupResourceType) findMember(ctx context.Context, memberId string) (string, error) {
	g.uid2dnMtx.Lock()
	if dn, ok := g.uid2dnCache[memberId]; ok {
		g.uid2dnMtx.Unlock()
		return dn, nil
	}
	g.uid2dnMtx.Unlock()

	filter := fmt.Sprintf(groupMemberUIDFilter, ldap3.EscapeFilter(memberId))
	dn, err := g.findMemberByFilter(ctx, memberId, filter)
	if err != nil {
		return "", err
	}
	if dn != "" {
		return dn, nil
	}

	filter = fmt.Sprintf(groupMemberCommonNameFilter, ldap3.EscapeFilter(memberId))
	dn, err = g.findMemberByFilter(ctx, memberId, filter)
	if err != nil {
		return "", err
	}
	if dn != "" {
		return dn, nil
	}
	return "", nil
}

func (g *groupResourceType) findMemberByFilter(ctx context.Context, memberId string, filter string) (string, error) {
	l := ctxzap.Extract(ctx)

	memberEntry, _, err := g.client.LdapSearch(
		ctx,
		ldap3.ScopeWholeSubtree,
		g.userSearchDN,
		filter,
		nil,
		"",
		1,
	)

	if err != nil {
		l.Error("ldap-connector: expanding group: failed to get user", zap.String("member_id", memberId), zap.Error(err))
		// returns err, since this is a network error
		return "", err
	}

	if len(memberEntry) == 0 {
		l.Error("ldap-connector: expanding group: failed to find user", zap.String("member_id", memberId), zap.String("search_filter", filter))
		return "", nil
	}

	if len(memberEntry) > 1 {
		err := fmt.Errorf("multiple users found by search")
		l.Error("ldap-connector: expanding group: multiple users found by search", zap.String("member_id", memberId), zap.String("search_filter", filter))
		// note: returning error since this feels like a
		// developer error?
		return "", err
	}

	mem := memberEntry[0]
	memDN, err := ldap.CanonicalizeDN(mem.DN)
	if err != nil {
		l.Error("ldap-connector: expanding group: invalid DN", zap.String("member_id", memberId), zap.String("search_filter", filter), zap.Error(err), zap.String("member_dn", mem.DN))
		// note: returning error since this feels like a
		// developer error?
		return "", err
	}

	memberDN := memDN.String()
	g.uid2dnMtx.Lock()
	g.uid2dnCache[memberId] = memberDN
	g.uid2dnMtx.Unlock()
	return memberDN, nil
}

func (g *groupResourceType) getGroup(ctx context.Context, groupDN string) (*ldap3.Entry, error) {
	gdn, err := ldap.CanonicalizeDN(groupDN)
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: invalid group DN: '%s' in getGroup: %w", groupDN, err)
	}

	return g.client.LdapGet(
		ctx,
		gdn,
		groupFilter,
		nil,
	)
}

func (g *groupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	if principal.Id.ResourceType != resourceTypeUser.Id {
		return nil, fmt.Errorf("baton-ldap: only users can have group membership granted")
	}

	groupDN := entitlement.Resource.Id.Resource

	modifyRequest := ldap3.NewModifyRequest(groupDN, nil)

	group, err := g.getGroup(ctx, groupDN)
	if err != nil {
		return nil, err
	}

	if slices.Contains(group.GetAttributeValues("objectClass"), "posixGroup") {
		dn, err := ldap.CanonicalizeDN(principal.Id.Resource)
		if err != nil {
			return nil, err
		}
		username := []string{dn.RDNs[0].Attributes[0].Value}
		modifyRequest.Add(attrGroupMemberPosix, username)
	} else {
		principalDNArr := []string{principal.Id.Resource}
		modifyRequest.Add(attrGroupUniqueMember, principalDNArr)
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

	// TODO: check whether membership is via memberUid, uniqueMember, or member, and modify accordingly
	if slices.Contains(group.GetAttributeValues("objectClass"), "posixGroup") {
		dn, err := ldap.CanonicalizeDN(principal.Id.Resource)
		if err != nil {
			return nil, err
		}
		username := []string{dn.RDNs[0].Attributes[0].Value}
		modifyRequest.Delete(attrGroupMemberPosix, username)
	} else {
		principalDNArr := []string{principal.Id.Resource}
		modifyRequest.Delete(attrGroupUniqueMember, principalDNArr)
	}

	// revoke group membership from the principal
	err = g.client.LdapModify(
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
		return nil, fmt.Errorf("ldap-connector: failed to revoke group membership from user: %w", err)
	}

	return nil, nil
}

func groupBuilder(client *ldap.Client, groupSearchDN *ldap3.DN,
	userSearchDN *ldap3.DN) *groupResourceType {
	return &groupResourceType{
		groupSearchDN: groupSearchDN,
		userSearchDN:  userSearchDN,
		resourceType:  resourceTypeGroup,
		client:        client,
		uid2dnCache:   make(map[string]string),
	}
}
