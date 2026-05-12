package connector

import (
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestGroupGrantRevoke(t *testing.T) {
	ctx := t.Context()

	ctx = ctxzap.ToContext(ctx, zap.Must(zap.NewDevelopment()))

	connector, err := createConnector(ctx, t, "simple.ldif")
	require.NoError(t, err)

	gb := groupBuilder(connector.client, connector.config.GroupSearchDN, connector.config.UserSearchDN)

	groups, pt, _, err := gb.List(ctx, nil, &pagination.Token{})
	require.NoError(t, err)
	require.Len(t, groups, 2)
	require.Empty(t, pt)

	staffGroup := pluck(groups, func(g *v2.Resource) bool {
		return g.GetDisplayName() == "staff"
	})
	require.NotNil(t, staffGroup)

	testGroup := pluck(groups, func(g *v2.Resource) bool {
		return g.GetDisplayName() == "test"
	})
	require.NotNil(t, testGroup)

	ents, pt, _, err := gb.Entitlements(ctx, testGroup, &pagination.Token{})
	require.NoError(t, err)
	require.Empty(t, pt)
	require.Len(t, ents, 1)

	membershipEnt := ents[0]

	grants, pt, _, err := gb.Grants(ctx, testGroup, &pagination.Token{})
	require.NoError(t, err)
	require.Empty(t, pt)
	require.Len(t, grants, 1)

	rogerGrant := grants[0]
	_, err = gb.Revoke(ctx, rogerGrant)
	require.NoError(t, err)
	// test double revoke doesn't cause a hard error
	_, err = gb.Revoke(ctx, rogerGrant)
	require.NoError(t, err)

	// verify 0 grants
	grants, pt, _, err = gb.Grants(ctx, testGroup, &pagination.Token{})
	require.NoError(t, err)
	require.Empty(t, pt)
	require.Len(t, grants, 0)

	_, err = gb.Grant(ctx, rogerGrant.Principal, membershipEnt)
	require.NoError(t, err)
	// test double revoke doesn't cause a hard error
	_, err = gb.Grant(ctx, rogerGrant.Principal, membershipEnt)
	require.NoError(t, err)

	// verify 1 grant
	grants, pt, _, err = gb.Grants(ctx, testGroup, &pagination.Token{})
	require.NoError(t, err)
	require.Empty(t, pt)
	require.Len(t, grants, 1)

	// verify its roger!
	require.EqualExportedValues(t, rogerGrant.Principal, grants[0].Principal)
	require.EqualExportedValues(t, rogerGrant.Entitlement, grants[0].Entitlement)
	require.Equal(t, rogerGrant.Id, grants[0].Id)
}

func TestGroupPosixGidNumber(t *testing.T) {
	ctx := t.Context()

	ctx = ctxzap.ToContext(ctx, zap.Must(zap.NewDevelopment()))

	connector, err := createConnector(ctx, t, "primary_groups.ldif")
	require.NoError(t, err)

	gb := groupBuilder(connector.client, connector.config.GroupSearchDN, connector.config.UserSearchDN)

	groups, pt, _, err := gb.List(ctx, nil, &pagination.Token{})
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Empty(t, pt)

	staffGroup := pluck(groups, func(g *v2.Resource) bool {
		return g.GetDisplayName() == "staff"
	})
	require.NotNil(t, staffGroup)

	ents, pt, _, err := gb.Entitlements(ctx, staffGroup, &pagination.Token{})
	require.NoError(t, err)
	require.Empty(t, pt)
	require.Len(t, ents, 1)

	grants, pt, _, err := gb.Grants(ctx, staffGroup, &pagination.Token{})
	require.NoError(t, err)
	require.Empty(t, pt)
	require.Len(t, grants, 2)
}

func TestGroupOfURLsGrants(t *testing.T) {
	ctx := t.Context()
	ctx = ctxzap.ToContext(ctx, zap.Must(zap.NewDevelopment()))

	connector, err := setupDyngroupTest(ctx, t)
	require.NoError(t, err)

	gb := groupBuilder(connector.client, connector.config.GroupSearchDN, connector.config.UserSearchDN)

	groups, _, _, err := gb.List(ctx, nil, &pagination.Token{})
	require.NoError(t, err)
	require.Len(t, groups, 2)

	engineersGroup := pluck(groups, func(g *v2.Resource) bool {
		return g.GetDisplayName() == "engineers"
	})
	require.NotNil(t, engineersGroup)

	grants, _, _, err := gb.Grants(ctx, engineersGroup, &pagination.Token{})
	require.NoError(t, err)
	require.Len(t, grants, 2)

	var grantedDNS []string
	for _, g := range grants {
		grantedDNS = append(grantedDNS, g.Principal.Id.Resource)
	}
	require.ElementsMatch(t, []string{
		"cn=alice,ou=users,dc=example,dc=org",
		"cn=bob,ou=users,dc=example,dc=org",
	}, grantedDNS)
}

func TestGroupOfURLsGrantRevokeError(t *testing.T) {
	ctx := t.Context()
	ctx = ctxzap.ToContext(ctx, zap.Must(zap.NewDevelopment()))

	connector, err := setupDyngroupTest(ctx, t)
	require.NoError(t, err)

	gb := groupBuilder(connector.client, connector.config.GroupSearchDN, connector.config.UserSearchDN)

	groups, _, _, err := gb.List(ctx, nil, &pagination.Token{})
	require.NoError(t, err)

	engineersGroup := pluck(groups, func(g *v2.Resource) bool {
		return g.GetDisplayName() == "engineers"
	})
	require.NotNil(t, engineersGroup)

	ents, _, _, err := gb.Entitlements(ctx, engineersGroup, &pagination.Token{})
	require.NoError(t, err)
	require.Len(t, ents, 1)

	grants, _, _, err := gb.Grants(ctx, engineersGroup, &pagination.Token{})
	require.NoError(t, err)
	require.NotEmpty(t, grants)

	_, err = gb.Grant(ctx, grants[0].Principal, ents[0])
	require.Error(t, err)

	_, err = gb.Revoke(ctx, grants[0])
	require.Error(t, err)
}

func TestParseMemberURL(t *testing.T) {
	tests := []struct {
		name       string
		rawURL     string
		wantBase   string
		wantScope  int
		wantFilter string
		wantErr    bool
	}{
		{
			name:       "sub scope with filter",
			rawURL:     "ldap:///ou=users,dc=example,dc=org??sub?(employeeType=Engineering)",
			wantBase:   "ou=users,dc=example,dc=org",
			wantScope:  ldap3.ScopeWholeSubtree,
			wantFilter: "(employeeType=Engineering)",
		},
		{
			name:       "one scope",
			rawURL:     "ldap:///ou=users,dc=example,dc=org??one?(cn=alice)",
			wantBase:   "ou=users,dc=example,dc=org",
			wantScope:  ldap3.ScopeSingleLevel,
			wantFilter: "(cn=alice)",
		},
		{
			name:       "base scope defaults to objectClass=* filter",
			rawURL:     "ldap:///cn=alice,ou=users,dc=example,dc=org??base",
			wantBase:   "cn=alice,ou=users,dc=example,dc=org",
			wantScope:  ldap3.ScopeBaseObject,
			wantFilter: ldapFilterAnyObject,
		},
		{
			name:       "no scope defaults to sub",
			rawURL:     "ldap:///ou=users,dc=example,dc=org",
			wantBase:   "ou=users,dc=example,dc=org",
			wantScope:  ldap3.ScopeWholeSubtree,
			wantFilter: ldapFilterAnyObject,
		},
		{
			name:       "explicit empty filter defaults to objectClass=*",
			rawURL:     "ldap:///ou=users,dc=example,dc=org??sub?",
			wantBase:   "ou=users,dc=example,dc=org",
			wantScope:  ldap3.ScopeWholeSubtree,
			wantFilter: ldapFilterAnyObject,
		},
		{
			name:       "percent-encoded filter is decoded",
			rawURL:     "ldap:///ou=users,dc=example,dc=org??sub?(cn=John%20Doe)",
			wantBase:   "ou=users,dc=example,dc=org",
			wantScope:  ldap3.ScopeWholeSubtree,
			wantFilter: "(cn=John Doe)",
		},
		{
			name:    "invalid URL",
			rawURL:  "://bad url",
			wantErr: true,
		},
		{
			name:    "unknown scope",
			rawURL:  "ldap:///ou=users,dc=example,dc=org??bogus?(objectClass=*)",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base, scope, filter, err := parseMemberURL(tc.rawURL)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantBase, base)
			require.Equal(t, tc.wantScope, scope)
			require.Equal(t, tc.wantFilter, filter)
		})
	}
}
