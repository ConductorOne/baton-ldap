package connector

import (
	"context"
	"strings"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/openldap"
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
		"objectClass": []interface{}{"inetOrgPerson", ldapObjectClassTop},
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

func countUserPassword(attrs []ldap3.Attribute) int {
	n := 0
	for _, a := range attrs {
		if strings.EqualFold(a.Type, attrUserPassword) {
			n++
		}
	}
	return n
}

// TestWithUserPassword pins the dedup/inject behavior that lets CreateAccount
// fold the managed password into the initial add. Runs without Docker.
func TestWithUserPassword(t *testing.T) {
	sn := ldap3.Attribute{Type: "sn", Vals: []string{"Doe"}}
	cn := ldap3.Attribute{Type: "cn", Vals: []string{"Jane"}}

	// A hard-coded userPassword mapping is stripped and replaced by the managed one.
	got := withUserPassword([]ldap3.Attribute{sn, {Type: "userPassword", Vals: []string{"hardcoded"}}, cn}, "managed")
	require.Equal(t, 1, countUserPassword(got))
	require.Len(t, got, 3) // sn, cn, managed userPassword
	for _, a := range got {
		if strings.EqualFold(a.Type, attrUserPassword) {
			require.Equal(t, []string{"managed"}, a.Vals)
		}
	}
	// Non-password attributes are preserved.
	require.Equal(t, 1, countType(got, "sn"))
	require.Equal(t, 1, countType(got, "cn"))

	// Case-insensitive match, multiple pre-existing entries -> all removed, one appended.
	got = withUserPassword([]ldap3.Attribute{
		{Type: "USERPASSWORD", Vals: []string{"a"}},
		sn,
		{Type: "userpassword", Vals: []string{"b"}},
	}, "managed")
	require.Equal(t, 1, countUserPassword(got))
	require.Len(t, got, 2)

	// Empty password (NoPassword) -> all userPassword entries removed, none appended.
	got = withUserPassword([]ldap3.Attribute{sn, {Type: "userPassword", Vals: []string{"hardcoded"}}}, "")
	require.Equal(t, 0, countUserPassword(got))
	require.Len(t, got, 1)
	require.Equal(t, "sn", got[0].Type)

	// No userPassword present + empty password -> unchanged.
	got = withUserPassword([]ldap3.Attribute{sn, cn}, "")
	require.Equal(t, 0, countUserPassword(got))
	require.Len(t, got, 2)
}

func countType(attrs []ldap3.Attribute, t string) int {
	n := 0
	for _, a := range attrs {
		if a.Type == t {
			n++
		}
	}
	return n
}

// bindAs dials the container and attempts a simple bind, proving whether the
// given password authenticates the DN.
func bindAs(ctx context.Context, t *testing.T, container *openldap.OpenLDAPContainer, dn, password string) error {
	t.Helper()
	connStr, err := container.ConnectionString(ctx)
	require.NoError(t, err)
	conn, err := ldap3.DialURL(connStr)
	require.NoError(t, err)
	defer conn.Close()
	return conn.Bind(dn, password)
}

// TestCreateAccountRandomPasswordSetAtCreation verifies the generated password
// is set on the entry at creation time (folded into the add), not via a later
// modify. Requires Docker (testcontainers) — runs in CI.
func TestCreateAccountRandomPasswordSetAtCreation(t *testing.T) {
	ctx := ctxzap.ToContext(context.Background(), zap.Must(zap.NewDevelopment()))

	connector, container, err := createConnectorWithContainer(ctx, t, "")
	require.NoError(t, err)

	ub := userBuilder(connector.client, connector.config.UserSearchDN, connector.config.DisableOperationalAttrs)

	profile, err := structpb.NewStruct(map[string]interface{}{
		"suffix":      "dc=example,dc=org",
		"path":        "ou=users",
		"rdnKey":      "cn",
		"rdnValue":    "randompwduser",
		"sn":          "User",
		"objectClass": []interface{}{"inetOrgPerson", ldapObjectClassTop},
	})
	require.NoError(t, err)

	accountInfo := &v2.AccountInfo{}
	accountInfo.SetProfile(profile)

	rp := &v2.LocalCredentialOptions_RandomPassword{}
	rp.SetLength(16)
	credOpts := &v2.LocalCredentialOptions{}
	credOpts.SetRandomPassword(rp)

	resp, ptd, _, err := ub.CreateAccount(ctx, accountInfo, credOpts)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, ptd, 1)
	generated := string(ptd[0].GetBytes())
	require.NotEmpty(t, generated)

	dn := "cn=randompwduser,ou=users,dc=example,dc=org"
	require.NoError(t, bindAs(ctx, t, container, dn, generated),
		"new account must be bindable with the generated password set at creation")
}

// TestCreateAccountDedupsHardcodedUserPassword verifies a hard-coded
// userPassword mapping is superseded by the C1-managed password (the account
// binds with the generated value, not the hard-coded one). Requires Docker.
func TestCreateAccountDedupsHardcodedUserPassword(t *testing.T) {
	ctx := ctxzap.ToContext(context.Background(), zap.Must(zap.NewDevelopment()))

	connector, container, err := createConnectorWithContainer(ctx, t, "")
	require.NoError(t, err)

	ub := userBuilder(connector.client, connector.config.UserSearchDN, connector.config.DisableOperationalAttrs)

	const hardcoded = "HardCoded123!"
	profile, err := structpb.NewStruct(map[string]interface{}{
		"suffix":               "dc=example,dc=org",
		"path":                 "ou=users",
		"rdnKey":               "cn",
		"rdnValue":             "deduptestuser",
		"sn":                   "User",
		"objectClass":          []interface{}{"inetOrgPerson", ldapObjectClassTop},
		"additionalAttributes": map[string]interface{}{"userPassword": hardcoded},
	})
	require.NoError(t, err)

	accountInfo := &v2.AccountInfo{}
	accountInfo.SetProfile(profile)

	rp := &v2.LocalCredentialOptions_RandomPassword{}
	rp.SetLength(16)
	credOpts := &v2.LocalCredentialOptions{}
	credOpts.SetRandomPassword(rp)

	resp, ptd, _, err := ub.CreateAccount(ctx, accountInfo, credOpts)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, ptd, 1)
	generated := string(ptd[0].GetBytes())
	require.NotEqual(t, hardcoded, generated)

	dn := "cn=deduptestuser,ou=users,dc=example,dc=org"
	require.NoError(t, bindAs(ctx, t, container, dn, generated),
		"account must bind with the managed password")
	require.Error(t, bindAs(ctx, t, container, dn, hardcoded),
		"hard-coded mapping value must not have been used as the password")
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
