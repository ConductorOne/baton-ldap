package connector

import (
	"context"
	"testing"

	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestRoleGrantRevoke(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()

	ctx = ctxzap.ToContext(ctx, zap.Must(zap.NewDevelopment()))

	connector, err := createConnector(ctx, t, "roles.ldif")
	require.NoError(t, err)

	rb := roleBuilder(connector.client, connector.config.RoleSearchDN)

	roles, pt, _, err := rb.List(ctx, nil, &pagination.Token{})
	require.NoError(t, err)
	require.Len(t, roles, 1)
	require.Empty(t, pt)
	require.Equal(t, roles[0].GetDisplayName(), "managers")

	managerRole := roles[0]

	ents, pt, _, err := rb.Entitlements(ctx, managerRole, &pagination.Token{})
	require.NoError(t, err)
	require.Empty(t, pt)
	require.Len(t, ents, 1)

	membershipEnt := ents[0]

	grants, pt, _, err := rb.Grants(ctx, managerRole, &pagination.Token{})
	require.NoError(t, err)
	require.Empty(t, pt)
	require.Len(t, grants, 1)

	rogerGrant := grants[0]
	_, err = rb.Revoke(ctx, rogerGrant)
	require.NoError(t, err)
	// test double revoke doesn't cause a hard error
	_, err = rb.Revoke(ctx, rogerGrant)
	require.NoError(t, err)

	// verify 0 grants
	grants, pt, _, err = rb.Grants(ctx, managerRole, &pagination.Token{})
	require.NoError(t, err)
	require.Empty(t, pt)
	require.Len(t, grants, 0)

	_, err = rb.Grant(ctx, rogerGrant.Principal, membershipEnt)
	require.NoError(t, err)
	// test double revoke doesn't cause a hard error
	_, err = rb.Grant(ctx, rogerGrant.Principal, membershipEnt)
	require.NoError(t, err)

	// verify 1 grant
	grants, pt, _, err = rb.Grants(ctx, managerRole, &pagination.Token{})
	require.NoError(t, err)
	require.Empty(t, pt)
	require.Len(t, grants, 1)

	// verify its roger!
	require.EqualExportedValues(t, rogerGrant.Principal, grants[0].Principal)
	require.EqualExportedValues(t, rogerGrant.Entitlement, grants[0].Entitlement)
	require.Equal(t, rogerGrant.Id, grants[0].Id)
}
