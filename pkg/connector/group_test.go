package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/stretchr/testify/require"
)

func TestGroupGrantRevoke(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()

	connector, err := createConnector(ctx, t, "simple..ldif")
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

func pluck[T any](slice []T, fn func(v T) bool) T {
	var emptyT T
	for _, v := range slice {
		if fn(v) {
			return v
		}
	}
	return emptyT
}
