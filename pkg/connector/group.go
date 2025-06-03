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

var objectClassesToResourceTypes = map[string]*v2.ResourceType{
	"group":                resourceTypeGroup,
	"groupOfNames":         resourceTypeGroup,
	"groupOfUniqueNames":   resourceTypeGroup,
	"inetOrgPerson":        resourceTypeUser,
	"posixGroup":           resourceTypeGroup,
	"organizationalPerson": resourceTypeUser,
	"person":               resourceTypeUser,
	"user":                 resourceTypeUser,
}

const (
	groupObjectClasses = "(objectClass=groupOfUniqueNames)(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=group)"
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
	attrGroupObjectGUID   = "objectGUID"

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
	description := group.GetEqualFoldAttributeValue(attrGroupDescription)
	profile := map[string]interface{}{
		"path": groupDN,
	}

	groupRsTraitOptions := []rs.ResourceOption{}
	groupRsTraitOptions = append(groupRsTraitOptions, rs.WithExternalID(&v2.ExternalId{
		Id: group.DN,
	}))
	if description != "" {
		profile["group_description"] = description
		groupRsTraitOptions = append(groupRsTraitOptions, rs.WithDescription(description))
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
		groupRsTraitOptions...,
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

func (g *groupResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	l.Debug("getting group", zap.String("resource_id", resourceId.Resource))

	groupDN, err := ldap.CanonicalizeDN(resourceId.Resource)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap-connector: failed to canonicalize group DN: %w", err)
	}

	groupEntries, _, err := g.client.LdapSearch(ctx, ldap3.ScopeBaseObject, groupDN, groupFilter, allAttrs, "", ResourcesPageSize)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap-connector: failed to get group: %w", err)
	}

	if len(groupEntries) == 0 {
		return nil, nil, fmt.Errorf("ldap-connector: group not found")
	}

	groupEntry := groupEntries[0]

	gr, err := groupResource(ctx, groupEntry)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap-connector: failed to get group: %w", err)
	}

	return gr, nil, nil
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
func newGrantFromDN(groupResource *v2.Resource, dn string, resourceType *v2.ResourceType) *v2.Grant {
	grantOpts := []grant.GrantOption{}
	if resourceType == resourceTypeGroup {
		grantOpts = append(grantOpts, grant.WithAnnotation(&v2.GrantExpandable{
			EntitlementIds: []string{
				fmt.Sprintf("group:%s:member", dn),
			},
		}))
	}
	g := grant.NewGrant(
		// remove group profile from grant so we're not saving all group memberships in every grant
		&v2.Resource{
			Id: groupResource.Id,
		},
		groupMemberEntitlement,
		// remove user profile from grant so we're not saving repetitive user info in every grant
		&v2.ResourceId{
			ResourceType: resourceType.Id,
			Resource:     dn,
		},
		grantOpts...,
	)
	return g
}

func newGrantFromEntry(groupResource *v2.Resource, entry *ldap3.Entry) *v2.Grant {
	var dn string
	parsedDN, err := ldap.CanonicalizeDN(entry.DN)
	if err == nil {
		dn = parsedDN.String()
	} else {
		dn = entry.DN
	}

	for _, objectClass := range entry.GetAttributeValues("objectClass") {
		if resourceType, ok := objectClassesToResourceTypes[objectClass]; ok {
			return newGrantFromDN(groupResource, dn, resourceType)
		}
	}

	return newGrantFromDN(groupResource, dn, resourceTypeUser)
}

func (g *groupResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	groupDN, err := ldap.CanonicalizeDN(resource.Id.Resource)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ldap-connector: invalid group DN: '%s' in group grants: %w", resource.Id.Resource, err)
	}
	l = l.With(zap.Stringer("group_dn", groupDN))

	var ldapGroup *ldap3.Entry
	externalId := resource.GetExternalId()
	if externalId != nil {
		ldapGroup, err = g.client.LdapGetWithStringDN(
			ctx,
			externalId.Id,
			groupFilter,
			nil,
		)
	} else {
		ldapGroup, err = g.client.LdapGet(
			ctx,
			groupDN,
			groupFilter,
			nil,
		)
	}

	if err != nil {
		l.Error("ldap-connector: failed to list group members", zap.String("group_dn", resource.Id.Resource), zap.Error(err))

		// Some LDAP servers lie and return a group DN that doesn't actually exist.
		// Or the group got deleted between List() and Grants().
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
			member, _, err := g.client.LdapSearch(
				ctx,
				ldap3.ScopeWholeSubtree,
				parsedDN,
				"",
				nil,
				"",
				1,
			)
			if err != nil {
				l.Error("ldap-connector: failed to get group member", zap.String("group", groupDN.String()), zap.String("member_id", memberId), zap.Error(err))
			}
			var g *v2.Grant
			if len(member) == 1 {
				g = newGrantFromEntry(resource, member[0])
			} else {
				// Fall back to creating a grant and assuming it's for a user.
				g = newGrantFromDN(resource, parsedDN.String(), resourceTypeUser)
			}
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
		g := newGrantFromDN(resource, memberDN, resourceTypeUser)
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
			nextPage,
			ResourcesPageSize,
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
			g := newGrantFromDN(resource, userDN.String(), resourceTypeUser)
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

	groupObjectGUID := parseValue(group, []string{attrGroupObjectGUID})
	principalDNArr := []string{principal.Id.Resource}

	switch {
	case slices.Contains(group.GetAttributeValues("objectClass"), "posixGroup"):
		dn, err := ldap.CanonicalizeDN(principal.Id.Resource)
		if err != nil {
			return nil, err
		}
		username := []string{dn.RDNs[0].Attributes[0].Value}
		modifyRequest.Add(attrGroupMemberPosix, username)

	case slices.Contains(group.GetAttributeValues("objectClass"), "ipausergroup") || groupObjectGUID != "":
		modifyRequest.Add(attrGroupMember, principalDNArr)

	default:
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

	groupObjectGUID := parseValue(group, []string{attrGroupObjectGUID})
	principalDNArr := []string{principal.Id.Resource}

	// TODO: check whether membership is via memberUid, uniqueMember, or member, and modify accordingly
	switch {
	case slices.Contains(group.GetAttributeValues("objectClass"), "posixGroup"):
		dn, err := ldap.CanonicalizeDN(principal.Id.Resource)
		if err != nil {
			return nil, err
		}
		username := []string{dn.RDNs[0].Attributes[0].Value}
		modifyRequest.Delete(attrGroupMemberPosix, username)

	case slices.Contains(group.GetAttributeValues("objectClass"), "ipausergroup") || groupObjectGUID != "":
		modifyRequest.Delete(attrGroupMember, principalDNArr)

	default:
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
