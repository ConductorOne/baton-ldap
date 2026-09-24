package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Integration coverage for the group membership write path. These tests drive a
// real directory (testcontainers), so they need a container runtime and run in CI
// only.

const (
	fixtureStaffDN       = "cn=staff,ou=groups,dc=example,dc=org"
	fixtureUniqueNamesDN = "cn=uniquenames,ou=groups,dc=example,dc=org"
	fixturePosixDN       = "cn=posix,ou=groups,dc=example,dc=org"
	fixtureInnerDN       = "cn=inner,ou=groups,dc=example,dc=org"
	fixtureOuterDN       = "cn=outer,ou=groups,dc=example,dc=org"

	fixtureAliceDN = "cn=alice,ou=users,dc=example,dc=org"
	fixtureBobDN   = "cn=bob,ou=users,dc=example,dc=org"
	fixtureCarolDN = "cn=carol,ou=users,dc=example,dc=org"
)

func groupMembershipFixture(ctx context.Context, t *testing.T) (*groupResourceType, *LDAP) {
	t.Helper()

	ctx = ctxzap.ToContext(ctx, zap.Must(zap.NewDevelopment()))

	connector, err := createConnector(ctx, t, "group_membership.ldif")
	require.NoError(t, err)

	gb := groupBuilder(connector.client, connector.config.GroupSearchDN, connector.config.UserSearchDN,
		connector.config.EffectiveGroupMemberAttribute())

	return gb, connector
}

// groupResourceFor finds a group by DN through the connector's own List, so the
// tests act on the resource C1 would hold.
func groupResourceFor(ctx context.Context, t *testing.T, gb *groupResourceType, dn string) *v2.Resource {
	t.Helper()

	groups, _, _, err := gb.List(ctx, nil, &pagination.Token{})
	require.NoError(t, err)

	group := pluck(groups, func(g *v2.Resource) bool { return g.Id.Resource == dn })
	require.NotNil(t, group, "group %s is not in the connector's list", dn)

	return group
}

func membershipEntitlementFor(ctx context.Context, t *testing.T, gb *groupResourceType, group *v2.Resource) *v2.Entitlement {
	t.Helper()

	ents, _, _, err := gb.Entitlements(ctx, group, &pagination.Token{})
	require.NoError(t, err)
	require.Len(t, ents, 1)

	return ents[0]
}

// userPrincipal builds the principal C1 would send: a user resource whose
// resource id is the DN.
func userPrincipal(dn string) *v2.Resource {
	return &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeUser.Id,
			Resource:     dn,
		},
	}
}

func membershipGrant(dn string, entitlement *v2.Entitlement) *v2.Grant {
	return &v2.Grant{Entitlement: entitlement, Principal: userPrincipal(dn)}
}

// groupEntryValues reads the group's raw values for one attribute, which is what
// the connector's write has to be visible in.
func groupEntryValues(ctx context.Context, t *testing.T, connector *LDAP, groupDN string, attr string) []string {
	t.Helper()

	entry, err := connector.client.LdapGet(ctx, mustParseDN(t, groupDN), "", nil)
	require.NoError(t, err)

	return entry.GetEqualFoldAttributeValues(attr)
}

func grantedPrincipals(ctx context.Context, t *testing.T, gb *groupResourceType, group *v2.Resource) []string {
	t.Helper()

	grants, _, _, err := gb.Grants(ctx, group, &pagination.Token{})
	require.NoError(t, err)

	dns := make([]string, 0, len(grants))
	for _, g := range grants {
		dns = append(dns, g.Principal.Id.Resource)
	}

	return dns
}

// TestGroupOfNamesRevokeRemovesMember is the assertion for the defect this change
// fixes: on a groupOfNames group the previous implementation deleted
// uniqueMember, the directory answered 16 ("attribute not present"), the
// connector's modify wrapper swallowed it, and Revoke reported success while the
// member stayed in `member`. It fails on main.
func TestGroupOfNamesRevokeRemovesMember(t *testing.T) {
	ctx := t.Context()
	gb, connector := groupMembershipFixture(ctx, t)

	group := groupResourceFor(ctx, t, gb, fixtureStaffDN)
	entitlement := membershipEntitlementFor(ctx, t, gb, group)

	require.Contains(t, grantedPrincipals(ctx, t, gb, group), fixtureAliceDN)

	_, err := gb.Revoke(ctx, membershipGrant(fixtureAliceDN, entitlement))
	require.NoError(t, err)

	require.NotContains(t, grantedPrincipals(ctx, t, gb, group), fixtureAliceDN,
		"the membership must be gone from what the read path reports")
	require.NotContains(t, groupEntryValues(ctx, t, connector, fixtureStaffDN, attrGroupMember), fixtureAliceDN)
	require.Contains(t, groupEntryValues(ctx, t, connector, fixtureStaffDN, attrGroupMember), fixtureBobDN,
		"the other member must be untouched")
	require.Empty(t, groupEntryValues(ctx, t, connector, fixtureStaffDN, attrGroupUniqueMember))
}

// TestGroupOfNamesGrantLandsInMember is the grant half: an empty groupOfNames
// group learns `member` from its object classes, and the write is confirmed
// against the read path.
func TestGroupOfNamesGrantLandsInMember(t *testing.T) {
	ctx := t.Context()
	gb, connector := groupMembershipFixture(ctx, t)

	group := groupResourceFor(ctx, t, gb, fixtureStaffDN)
	entitlement := membershipEntitlementFor(ctx, t, gb, group)

	_, err := gb.Grant(ctx, userPrincipal(fixtureCarolDN), entitlement)
	require.NoError(t, err)

	require.Contains(t, groupEntryValues(ctx, t, connector, fixtureStaffDN, attrGroupMember), fixtureCarolDN)
	require.Contains(t, grantedPrincipals(ctx, t, gb, group), fixtureCarolDN)
}

// TestPosixGroupGrantLandsInMemberUid covers the inferred memberUid choice: the
// group carries no membership at all, so its object classes decide, and the value
// written is the principal's uid (the entry has no stored form to follow).
func TestPosixGroupGrantLandsInMemberUid(t *testing.T) {
	ctx := t.Context()
	gb, connector := groupMembershipFixture(ctx, t)

	group := groupResourceFor(ctx, t, gb, fixturePosixDN)
	entitlement := membershipEntitlementFor(ctx, t, gb, group)

	_, err := gb.Grant(ctx, userPrincipal(fixtureAliceDN), entitlement)
	require.NoError(t, err)

	require.Contains(t, groupEntryValues(ctx, t, connector, fixturePosixDN, attrGroupMemberPosix), "alice")
	require.Empty(t, groupEntryValues(ctx, t, connector, fixturePosixDN, attrGroupMember))
	require.Contains(t, grantedPrincipals(ctx, t, gb, group), fixtureAliceDN)
}

// TestGroupOfUniqueNamesGrantLandsInUniqueMember covers the class that used to be
// the unconditional default, and is now one of the guesses rather than a rule.
func TestGroupOfUniqueNamesGrantLandsInUniqueMember(t *testing.T) {
	ctx := t.Context()
	gb, connector := groupMembershipFixture(ctx, t)

	group := groupResourceFor(ctx, t, gb, fixtureUniqueNamesDN)
	entitlement := membershipEntitlementFor(ctx, t, gb, group)

	_, err := gb.Grant(ctx, userPrincipal(fixtureBobDN), entitlement)
	require.NoError(t, err)

	require.Contains(t, groupEntryValues(ctx, t, connector, fixtureUniqueNamesDN, attrGroupUniqueMember), fixtureBobDN)
	require.Contains(t, grantedPrincipals(ctx, t, gb, group), fixtureBobDN)
}

// TestGroupMembershipIdempotency covers the two annotations: granting a
// membership that is already there, and revoking one that is not.
func TestGroupMembershipIdempotency(t *testing.T) {
	ctx := t.Context()
	gb, _ := groupMembershipFixture(ctx, t)

	group := groupResourceFor(ctx, t, gb, fixtureStaffDN)
	entitlement := membershipEntitlementFor(ctx, t, gb, group)

	annos, err := gb.Grant(ctx, userPrincipal(fixtureAliceDN), entitlement)
	require.NoError(t, err)
	require.True(t, annos.Contains(&v2.GrantAlreadyExists{}), "an existing member is an already-exists, not a write")

	annos, err = gb.Revoke(ctx, membershipGrant(fixtureCarolDN, entitlement))
	require.NoError(t, err)
	require.True(t, annos.Contains(&v2.GrantAlreadyRevoked{}), "a non-member is an already-revoked, not a delete")

	// The group is unchanged by either.
	require.Contains(t, grantedPrincipals(ctx, t, gb, group), fixtureAliceDN)
	require.NotContains(t, grantedPrincipals(ctx, t, gb, group), fixtureCarolDN)
}

// TestNestedGroupRevokeReportsInherited covers the inherited-membership guard end
// to end: outer holds inner, inner holds carol, so the read path reports carol as
// a member of outer, and no write to outer's own attributes can remove that. The
// revoke must say so instead of reporting success.
func TestNestedGroupRevokeReportsInherited(t *testing.T) {
	ctx := t.Context()
	gb, connector := groupMembershipFixture(ctx, t)

	group := groupResourceFor(ctx, t, gb, fixtureOuterDN)
	entitlement := membershipEntitlementFor(ctx, t, gb, group)

	_, err := gb.Revoke(ctx, membershipGrant(fixtureCarolDN, entitlement))
	require.Error(t, err)
	require.ErrorContains(t, err, "inherited")
	require.ErrorContains(t, err, fixtureInnerDN)

	// A direct grant for the same principal is still a direct write: an inherited
	// membership must not make the grant think the work is already done.
	annos, err := gb.Grant(ctx, userPrincipal(fixtureCarolDN), entitlement)
	require.NoError(t, err)
	require.False(t, annos != nil && annos.Contains(&v2.GrantAlreadyExists{}))
	require.Contains(t, grantedPrincipals(ctx, t, gb, group), fixtureCarolDN)

	// The revoke of that direct membership removes the value it wrote, but it
	// cannot finish the job: carol is still a member of outer through inner, so the
	// answer names the remaining source instead of reporting a success the next
	// sync would contradict.
	_, err = gb.Revoke(ctx, membershipGrant(fixtureCarolDN, entitlement))
	require.Error(t, err)
	require.ErrorContains(t, err, "inherited")
	require.ErrorContains(t, err, fixtureInnerDN)
	require.NotContains(t, groupEntryValues(ctx, t, connector, fixtureOuterDN, attrGroupMember), fixtureCarolDN,
		"the direct value this call wrote must be gone")
	require.Contains(t, grantedPrincipals(ctx, t, gb, group), fixtureCarolDN,
		"the inherited membership remains, and the answer must say so")
}

// TestPrimaryGroupRevokeReportsPrimaryGroup covers the other guard: the
// membership the read path reports comes from the user's own gidNumber, which no
// membership write can remove.
func TestPrimaryGroupRevokeReportsPrimaryGroup(t *testing.T) {
	ctx := t.Context()
	ctx = ctxzap.ToContext(ctx, zap.Must(zap.NewDevelopment()))

	connector, err := createConnector(ctx, t, "primary_groups.ldif")
	require.NoError(t, err)

	gb := groupBuilder(connector.client, connector.config.GroupSearchDN, connector.config.UserSearchDN,
		connector.config.EffectiveGroupMemberAttribute())

	group := groupResourceFor(ctx, t, gb, "cn=staff,ou=groups,dc=example,dc=org")
	entitlement := membershipEntitlementFor(ctx, t, gb, group)

	// Every user with gidNumber 500 is a member of staff through their primary
	// group, and none of them is in a membership attribute.
	grants, _, _, err := gb.Grants(ctx, group, &pagination.Token{})
	require.NoError(t, err)
	require.NotEmpty(t, grants)

	_, err = gb.Revoke(ctx, &v2.Grant{Entitlement: entitlement, Principal: grants[0].Principal})
	require.Error(t, err)
	require.ErrorContains(t, err, "primary group")
}

// TestRfc2307bisCoexistGrantFollowsContent covers the entry that made a static
// class-to-attribute mapping impossible: a posixGroup that coexists with a DN
// group class, with membership already stored as memberUid. The write must follow
// the entry's content, not the class list.
//
// Loading rfc2307bis is what makes the combination legal (RFC 2307's posixGroup is
// STRUCTURAL, so {posixGroup, groupOfNames} is rejected there with result 65). The
// bitnami image may not ship the schema at all, and a run without it is skipped
// rather than failed: the case is here so it runs wherever the schema exists.
func TestRfc2307bisCoexistGrantFollowsContent(t *testing.T) {
	ctx := t.Context()
	ctx = ctxzap.ToContext(ctx, zap.Must(zap.NewDevelopment()))

	connector, container, err := createConnectorWithContainer(ctx, t, "group_membership.ldif")
	require.NoError(t, err)

	exitCode, _, err := container.Exec(ctx,
		[]string{"ldapadd", "-Y", "EXTERNAL",
			"-H", "ldapi://%2Fopt%2Fbitnami%2Fopenldap%2Fvar%2Frun%2Fldapi",
			"-f", "/opt/bitnami/openldap/etc/schema/rfc2307bis.ldif"},
	)
	if err != nil || exitCode != 0 {
		t.Skipf("this image has no loadable rfc2307bis schema (exit %d, err %v)", exitCode, err)
	}

	const coexistDN = "cn=coexist,ou=groups,dc=example,dc=org"
	addReq := ldap3.NewAddRequest(coexistDN, nil)
	addReq.Attribute("objectClass", []string{"top", "groupOfNames", "posixGroup"})
	addReq.Attribute("cn", []string{"coexist"})
	addReq.Attribute("gidNumber", []string{"4100"})
	addReq.Attribute("memberUid", []string{"alice"})
	addReq.Attribute("member", []string{fixtureBobDN})
	if err := connector.client.LdapAdd(ctx, addReq); err != nil {
		t.Skipf("this directory does not accept a posixGroup+groupOfNames entry: %v", err)
	}

	gb := groupBuilder(connector.client, connector.config.GroupSearchDN, connector.config.UserSearchDN,
		connector.config.EffectiveGroupMemberAttribute())

	group := groupResourceFor(ctx, t, gb, coexistDN)
	entitlement := membershipEntitlementFor(ctx, t, gb, group)

	_, err = gb.Grant(ctx, userPrincipal(fixtureCarolDN), entitlement)
	require.NoError(t, err)

	require.Contains(t, groupEntryValues(ctx, t, connector, coexistDN, attrGroupMemberPosix), "carol",
		"the entry keeps its membership in memberUid, so the grant follows the content")
	require.NotContains(t, groupEntryValues(ctx, t, connector, coexistDN, attrGroupMember), fixtureCarolDN)
	require.Contains(t, grantedPrincipals(ctx, t, gb, group), fixtureCarolDN)

	// A revoke reaches the same place, and leaves the DN-valued member alone.
	_, err = gb.Revoke(ctx, membershipGrant(fixtureCarolDN, entitlement))
	require.NoError(t, err)
	require.NotContains(t, groupEntryValues(ctx, t, connector, coexistDN, attrGroupMemberPosix), "carol")
	require.Contains(t, groupEntryValues(ctx, t, connector, coexistDN, attrGroupMember), fixtureBobDN)
}

// TestMemberUIDThatResolvesToAnotherUser covers the uid/cn collision. The group
// stores memberUid: dave, which is the uid of cn=robert and the cn of cn=dave.
// findMember resolves a name by uid first, so the membership is robert's; counting
// the stored value as dave's membership would make Revoke delete another user's
// value from the group.
func TestMemberUIDThatResolvesToAnotherUser(t *testing.T) {
	ctx := t.Context()
	gb, connector := groupMembershipFixture(ctx, t)

	const (
		collisionDN = "cn=collision,ou=groups,dc=example,dc=org"
		robertDN    = "cn=robert,ou=users,dc=example,dc=org"
		daveDN      = "cn=dave,ou=users,dc=example,dc=org"
	)

	group := groupResourceFor(ctx, t, gb, collisionDN)
	entitlement := membershipEntitlementFor(ctx, t, gb, group)

	// The value belongs to robert, and the read path says so.
	require.Contains(t, grantedPrincipals(ctx, t, gb, group), robertDN)
	require.NotContains(t, grantedPrincipals(ctx, t, gb, group), daveDN)

	annos, err := gb.Revoke(ctx, membershipGrant(daveDN, entitlement))
	require.NoError(t, err)
	require.True(t, annos.Contains(&v2.GrantAlreadyRevoked{}), "dave is not a member; the value is robert's")

	require.Contains(t, groupEntryValues(ctx, t, connector, collisionDN, attrGroupMemberPosix), "dave",
		"another user's membership value must not be deleted")
	require.Contains(t, grantedPrincipals(ctx, t, gb, group), robertDN,
		"the read path must still report robert's membership")
}

// TestMemberUIDCollisionGrantWritesTheResolvedName covers the grant side of the
// uid/cn collision: the value the group holds for "dave" belongs to cn=robert, and
// "dave" is also cn=dave's cn. The grant must not write that value (the Add would
// come back 20, "the value is already there", and Grant would report already-exists
// having written nothing); it writes the name the read path resolves to dave
// instead.
func TestMemberUIDCollisionGrantWritesTheResolvedName(t *testing.T) {
	ctx := t.Context()
	gb, connector := groupMembershipFixture(ctx, t)

	const (
		collisionDN = "cn=collision,ou=groups,dc=example,dc=org"
		robertDN    = "cn=robert,ou=users,dc=example,dc=org"
		daveDN      = "cn=dave,ou=users,dc=example,dc=org"
	)

	group := groupResourceFor(ctx, t, gb, collisionDN)
	entitlement := membershipEntitlementFor(ctx, t, gb, group)

	annos, err := gb.Grant(ctx, userPrincipal(daveDN), entitlement)
	require.NoError(t, err)
	require.False(t, annos != nil && annos.Contains(&v2.GrantAlreadyExists{}),
		"nothing had been written for dave, so this must not answer already-exists")

	memberUIDs := groupEntryValues(ctx, t, connector, collisionDN, attrGroupMemberPosix)
	require.Contains(t, memberUIDs, "robertd", "dave's own resolved name must be written")
	require.Contains(t, memberUIDs, "dave", "robert's membership must be untouched")

	principals := grantedPrincipals(ctx, t, gb, group)
	require.Contains(t, principals, robertDN)
	require.Contains(t, principals, daveDN, "the read path must now report dave too")
}
