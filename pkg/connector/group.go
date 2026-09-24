package connector

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
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
)

var objectClassesToResourceTypes = map[string]*v2.ResourceType{
	"group":                resourceTypeGroup,
	"groupOfNames":         resourceTypeGroup,
	"groupOfUniqueNames":   resourceTypeGroup,
	objectClassGroupOfURLs: resourceTypeGroup,
	"inetOrgPerson":        resourceTypeUser,
	"posixGroup":           resourceTypeGroup,
	"organizationalPerson": resourceTypeUser,
	"person":               resourceTypeUser,
	"user":                 resourceTypeUser,
}

const (
	ldapFilterAnyObject    = "(objectClass=*)"
	objectClassGroupOfURLs = "groupOfURLs"

	groupObjectClasses = "(objectClass=groupOfUniqueNames)(objectClass=groupOfNames)(objectClass=groupOfURLs)(objectClass=posixGroup)(objectClass=group)"
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
	attrGroupMemberURL    = "memberURL"
	attrGroupDescription  = "description"

	groupMemberEntitlement = "member"
)

type groupResourceType struct {
	resourceType  *v2.ResourceType
	groupSearchDN *ldap3.DN
	userSearchDN  *ldap3.DN
	client        *ldap.Client

	// groupMemberAttribute pins the membership attribute a grant is written to,
	// or is empty when the attribute is learned per entry. See
	// group_membership.go.
	groupMemberAttribute string

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
		schemaFieldPath: groupDN,
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

	groupTraitOptions := []rs.GroupTraitOption{}
	// profile is a resource-level attribute in baton-sdk; set it on the resource.
	groupRsTraitOptions = append(groupRsTraitOptions, rs.WithResourceProfile(profile))

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

	bag, _, err := parsePageToken(token.Token, &v2.ResourceId{
		ResourceType: resourceTypeGroup.Id,
		Resource:     resource.Id.Resource,
	})
	if err != nil {
		return nil, "", nil, err
	}

	// If we are paginating through a groupOfURLs expansion, skip the group-entry
	// fetch — the memberURL and LDAP cursor are already encoded in the bag.
	if bag.ResourceTypeID() == objectClassGroupOfURLs {
		return g.grantsFromMemberURL(ctx, resource, nil, bag)
	}

	var ldapGroup *ldap3.Entry
	externalId := resource.GetExternalId() //nolint:staticcheck // Deprecated, but needed for raw DN fallback lookup.
	if externalId == nil {
		ldapGroup, err = g.client.LdapGet(
			ctx,
			groupDN,
			groupFilter,
			nil,
		)
	} else {
		ldapGroup, err = g.getGroupWithFallback(ctx, l, groupDN, externalId)
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

	if slices.Contains(ldapGroup.GetAttributeValues("objectClass"), objectClassGroupOfURLs) {
		return g.grantsFromMemberURL(ctx, resource, ldapGroup, bag)
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

func (g *groupResourceType) getGroupWithFallback(ctx context.Context, l *zap.Logger, groupDN *ldap3.DN, externalId *v2.ExternalId) (*ldap3.Entry, error) {
	ldapGroup, err := g.client.LdapGetWithStringDN(
		ctx,
		externalId.Id,
		groupFilter,
		nil,
	)

	if err != nil && ldap3.IsErrorAnyOf(err, ldap3.LDAPResultNoSuchObject) {
		l.Info("ldap-connector: failed to get group by raw DN, using fallback", zap.String("raw_dn", externalId.Id), zap.Error(err))
		return g.client.LdapGet(
			ctx,
			groupDN,
			groupFilter,
			nil,
		)
	}

	return ldapGroup, err
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
//
// It is the read path's resolver, and it caches across calls: a sync resolves the
// same login name many times, and its answers cannot change while the sync runs.
// The write path must not use this cache (see lookupMember).
func (g *groupResourceType) findMember(ctx context.Context, memberId string) (string, error) {
	g.uid2dnMtx.Lock()
	if dn, ok := g.uid2dnCache[memberId]; ok {
		g.uid2dnMtx.Unlock()
		return dn, nil
	}
	g.uid2dnMtx.Unlock()

	dn, err := g.lookupMember(ctx, memberId)
	if err != nil || dn == "" {
		return dn, err
	}

	g.uid2dnMtx.Lock()
	g.uid2dnCache[memberId] = dn
	g.uid2dnMtx.Unlock()

	return dn, nil
}

// lookupMember resolves a stored login name to a user DN -- uid first, then cn,
// exactly as the read path resolves one -- without consulting or filling the read
// path's cache.
//
// The write path uses this one. A connector in service mode runs for weeks, so a
// name that was re-pointed at a different entry after the first resolution would
// otherwise decide a write (which attribute to write, and whether the principal is
// already a member) from an answer that is no longer true.
func (g *groupResourceType) lookupMember(ctx context.Context, memberId string) (string, error) {
	dn, err := g.findMemberByFilter(ctx, memberId, fmt.Sprintf(groupMemberUIDFilter, ldap3.EscapeFilter(memberId)))
	if err != nil || dn != "" {
		return dn, err
	}

	return g.findMemberByFilter(ctx, memberId, fmt.Sprintf(groupMemberCommonNameFilter, ldap3.EscapeFilter(memberId)))
}

// findMemberByFilter runs one of the two login-name searches and returns the
// canonical DN of the single entry it matched, an empty string when nothing
// matched, and an error when more than one entry did (a directory whose uid or cn
// is not unique cannot have its login-name memberships resolved).
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

	return memDN.String(), nil
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

// grantsFromMemberURL expands the current memberURL page of a groupOfURLs entry into grants.
// group is the LDAP entry for the group; it is non-nil only on the first call (when
// the bag's current ResourceTypeID is still the initial group state). On continuation
// calls the memberURL and LDAP page cursor are read directly from the bag.
func (g *groupResourceType) grantsFromMemberURL(ctx context.Context, resource *v2.Resource, group *ldap3.Entry, bag *pagination.Bag) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	// On the first call the bag holds the initial group state. Replace it with one
	// page state per memberURL so subsequent SDK calls can skip the group-entry fetch.
	if bag.ResourceTypeID() != objectClassGroupOfURLs {
		memberURLs := group.GetAttributeValues(attrGroupMemberURL)
		if len(memberURLs) == 0 {
			return nil, "", nil, nil
		}
		// Pop the initial group state, then push URLs in reverse order so the
		// first URL is on top (current).
		bag.Pop()
		for i := len(memberURLs) - 1; i >= 0; i-- {
			bag.Push(pagination.PageState{
				ResourceTypeID: objectClassGroupOfURLs,
				ResourceID:     memberURLs[i],
			})
		}
	}

	rawURL := bag.ResourceID()
	ldapPage := bag.PageToken()

	base, scope, filter, err := parseMemberURL(rawURL)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ldap-connector: invalid memberURL %q: %w", rawURL, err)
	}

	entries, nextLDAPPage, err := g.client.LdapSearchWithStringDN(ctx, scope, base, filter, nil, ldapPage, ResourcesPageSize)
	if err != nil {
		l.Error("ldap-connector: memberURL search failed", zap.String("url", rawURL), zap.Error(err))
		return nil, "", nil, fmt.Errorf("ldap-connector: memberURL search failed: %w", err)
	}

	var rv []*v2.Grant
	for _, entry := range entries {
		gr := newGrantFromEntry(resource, entry)
		annos := annotations.Annotations(gr.GetAnnotations())
		annos.Update(&v2.GrantImmutable{})
		gr.SetAnnotations(annos)
		rv = append(rv, gr)
	}

	// NextToken either advances the LDAP cursor within this URL (nextLDAPPage != "")
	// or pops this URL to expose the next one. When all URLs are exhausted Marshal
	// returns "" which signals done to the SDK.
	nextToken, err := bag.NextToken(nextLDAPPage)
	if err != nil {
		return nil, "", nil, err
	}

	return rv, nextToken, nil, nil
}

// parseMemberURL parses an LDAP URL per RFC 4516.
// Format: ldap://[host]/base?attrs?scope?filter
// Returns the base DN, ldap scope constant, and filter string.
func parseMemberURL(rawURL string) (string, int, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", 0, "", fmt.Errorf("invalid LDAP URL: %w", err)
	}

	base := strings.TrimPrefix(u.Path, "/")

	// u.RawQuery holds everything after the first '?': attrs?scope?filter
	parts := strings.SplitN(u.RawQuery, "?", 3)

	scopeStr := ""
	if len(parts) > 1 {
		scopeStr = strings.ToLower(parts[1])
	}

	var scope int
	switch scopeStr {
	case "base":
		scope = ldap3.ScopeBaseObject
	case "one":
		scope = ldap3.ScopeSingleLevel
	case "sub", "":
		scope = ldap3.ScopeWholeSubtree
	default:
		return "", 0, "", fmt.Errorf("unknown scope %q in LDAP URL", scopeStr)
	}

	var filter string
	if len(parts) > 2 && parts[2] != "" {
		filter, err = url.PathUnescape(parts[2])
		if err != nil {
			return "", 0, "", fmt.Errorf("invalid percent-encoding in filter: %w", err)
		}
	} else {
		filter = ldapFilterAnyObject
	}

	return base, scope, filter, nil
}

func groupBuilder(client *ldap.Client, groupSearchDN *ldap3.DN,
	userSearchDN *ldap3.DN, groupMemberAttribute string) *groupResourceType {
	return &groupResourceType{
		groupSearchDN:        groupSearchDN,
		userSearchDN:         userSearchDN,
		resourceType:         resourceTypeGroup,
		client:               client,
		groupMemberAttribute: groupMemberAttribute,
		uid2dnCache:          make(map[string]string),
	}
}
