package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
)

// TestCreateAccountCommaInCN reproduces CXP-353: creating an account whose CN
// contains a comma must not fail when reading back the newly created entry.
func TestCreateAccountCommaInCN(t *testing.T) {
	ctx := ctxzap.ToContext(context.Background(), zap.Must(zap.NewDevelopment()))

	connector, err := createConnector(ctx, t, "")
	require.NoError(t, err)

	ub := userBuilder(connector.client, connector.config.UserSearchDN, connector.config.DisableOperationalAttrs)

	profile, err := structpb.NewStruct(map[string]interface{}{
		"suffix":      "dc=example,dc=org",
		"path":        "ou=users",
		"rdnKey":      "cn",
		"rdnValue":    "Smith, John",
		"sn":          "Smith",
		"objectClass": []interface{}{"inetOrgPerson", "top"},
	})
	require.NoError(t, err)

	accountInfo := &v2.AccountInfo{}
	accountInfo.SetProfile(profile)

	credOpts := &v2.LocalCredentialOptions{}
	credOpts.SetNoPassword(&v2.LocalCredentialOptions_NoPassword{})

	resp, _, _, err := ub.CreateAccount(ctx, accountInfo, credOpts)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestUserLastLogin(t *testing.T) {
	// 133597695554218221 == 05/09/2024 11:05:55 PM
	lastLoginTime, err := parseUserLastLogin("133597695554218221")
	require.NoError(t, err)
	require.Equal(t, "2024-05-09 23:05:55 +0000 UTC", lastLoginTime.String())

	lastLoginTime, err = parseUserLastLogin("20200804154203Z")
	require.NoError(t, err)
	require.Equal(t, "2020-08-04 15:42:03 +0000 UTC", lastLoginTime.String())

	_, err = parseUserLastLogin("Not a date")
	require.Error(t, err)
}
