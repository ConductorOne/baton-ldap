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

	ub := userBuilder(connector.client, connector.config.UserSearchDN, connector.config.DisableOperationalAttrs, connector.config.UserStatusAttributes)

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

// attrsToMap indexes an attribute list by type. It fails the test when any
// attribute carries no value, which is the property CXP-1123 is about: a
// zero-length value fails the whole LDAP Add on a Directory String attribute
// (result 21) and is stored verbatim on an IA5 String one.
func attrsToMap(t *testing.T, attrs []ldap3.Attribute) map[string][]string {
	t.Helper()
	out := make(map[string][]string, len(attrs))
	for _, a := range attrs {
		require.NotEmpty(t, a.Vals, "attribute %q was sent with no value", a.Type)
		out[a.Type] = a.Vals
	}
	return out
}

// TestExtractProfileOmitsEmptyValues pins CXP-1123: an optional field mapped
// into the create-account profile with an empty value must produce no LDAP
// attribute, while real values -- including non-string scalars -- must survive.
// Runs without Docker: extractProfile only touches its client for
// calculatePosixUIDNumber, which this profile leaves unset.
func TestExtractProfileOmitsEmptyValues(t *testing.T) {
	ctx := ctxzap.ToContext(context.Background(), zap.Must(zap.NewDevelopment()))
	u := &userResourceType{}

	profile, err := structpb.NewStruct(map[string]interface{}{
		// Required shape fields -- all reserved, none may become an attribute.
		"suffix":      "dc=example,dc=org",
		"path":        "ou=users",
		"rdnKey":      "cn",
		"rdnValue":    "jdoe",
		"objectClass": []interface{}{"inetOrgPerson", ldapObjectClassTop},
		// Real values -- must survive.
		"cn":       "jdoe",
		"sn":       "Doe",
		"isActive": false,
		// Unset optional fields -- must not become attributes. A null value
		// reaches here as nil because structpb stores it as a NullValue.
		"title":           "",
		"mail":            "",
		"description":     nil,
		"telephoneNumber": []interface{}{},
		"employeeNumber":  []interface{}{"", ""},
		// A list with one usable entry keeps only that entry.
		"givenName": []interface{}{"", "Jane"},
	})

	require.NoError(t, err)

	accountInfo := &v2.AccountInfo{}
	accountInfo.SetProfile(profile)

	dn, attrs, err := u.extractProfile(ctx, accountInfo)
	require.NoError(t, err)
	require.Equal(t, "cn=jdoe,ou=users,dc=example,dc=org", dn)

	got := attrsToMap(t, attrs)
	require.Equal(t, map[string][]string{
		"objectClass": {"inetOrgPerson", "top"},
		"cn":          {"jdoe"},
		"sn":          {"Doe"},
		"isActive":    {"false"},
		"givenName":   {"Jane"},
	}, got)

	for _, absent := range []string{
		"title", "mail", "description", "telephoneNumber", "employeeNumber",
		"suffix", "path", "rdnKey", "rdnValue", "login", "calculatePosixUIDNumber", "additionalAttributes",
	} {
		require.NotContains(t, got, absent)
	}
}

// TestExtractProfileObjectClass covers objectClass, the one mapped value the add
// cannot do without. A list that names no object class passes the type check in
// extractProfile, and toAttrIfNotEmpty would then drop the attribute entirely,
// leaving the directory to reject the add with an opaque result 65. Because the
// create-account task is not retryable, extractProfile reports it instead.
func TestExtractProfileObjectClass(t *testing.T) {
	ctx := ctxzap.ToContext(context.Background(), zap.Must(zap.NewDevelopment()))
	u := &userResourceType{}

	newProfile := func(t *testing.T, objectClass interface{}) *v2.AccountInfo {
		t.Helper()
		profile, err := structpb.NewStruct(map[string]interface{}{
			"suffix":      "dc=example,dc=org",
			"path":        "ou=users",
			"rdnKey":      "cn",
			"rdnValue":    "jdoe",
			"cn":          "jdoe",
			"sn":          "Doe",
			"objectClass": objectClass,
		})
		require.NoError(t, err)

		accountInfo := &v2.AccountInfo{}
		accountInfo.SetProfile(profile)
		return accountInfo
	}

	t.Run("a list naming no object class is rejected", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			objectClass interface{}
			want        string
		}{
			// The two rows the new guard covers. The message is the one the
			// existing type check already used for a missing objectClass.
			{name: "empty list", objectClass: []interface{}{}, want: "invalid/missing objectClass"},
			{name: "list of empty strings", objectClass: []interface{}{"", ""}, want: "invalid/missing objectClass"},
			// Pre-existing paths, asserted by exact message so a change to the
			// guard cannot quietly loosen them.
			{name: "missing", objectClass: nil, want: "invalid/missing objectClass"},
			{name: "scalar string", objectClass: "", want: "invalid/missing objectClass"},
			{name: "nil element", objectClass: []interface{}{nil}, want: "invalid objectClass"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, _, err := u.extractProfile(ctx, newProfile(t, tc.objectClass))
				require.EqualError(t, err, tc.want)
			})
		}
	})

	t.Run("empty entries are filtered from a list that still names a class", func(t *testing.T) {
		_, attrs, err := u.extractProfile(ctx, newProfile(t, []interface{}{"", "person"}))
		require.NoError(t, err)
		require.Equal(t, []string{"person"}, attrsToMap(t, attrs)["objectClass"])
	})
}

// TestExtractProfileOmitsEmptyAdditionalAttributes covers the second append
// site: values mapped under additionalAttributes follow the same rule.
func TestExtractProfileOmitsEmptyAdditionalAttributes(t *testing.T) {
	ctx := ctxzap.ToContext(context.Background(), zap.Must(zap.NewDevelopment()))
	u := &userResourceType{}

	profile, err := structpb.NewStruct(map[string]interface{}{
		"suffix":      "dc=example,dc=org",
		"path":        "",
		"rdnKey":      "cn",
		"rdnValue":    "jdoe",
		"sn":          "Doe",
		"objectClass": []interface{}{"inetOrgPerson", ldapObjectClassTop},
		"additionalAttributes": map[string]interface{}{
			"l":            "Austin",
			"title":        "",
			"department":   nil,
			"employeeType": []interface{}{"", nil},
		},
	})

	require.NoError(t, err)

	accountInfo := &v2.AccountInfo{}
	accountInfo.SetProfile(profile)

	_, attrs, err := u.extractProfile(ctx, accountInfo)
	require.NoError(t, err)

	got := attrsToMap(t, attrs)
	require.Equal(t, []string{"Austin"}, got["l"])
	require.NotContains(t, got, "title")
	require.NotContains(t, got, "department")
	require.NotContains(t, got, "employeeType")
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

	ub := userBuilder(connector.client, connector.config.UserSearchDN, connector.config.DisableOperationalAttrs, connector.config.UserStatusAttributes)

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

	ub := userBuilder(connector.client, connector.config.UserSearchDN, connector.config.DisableOperationalAttrs, connector.config.UserStatusAttributes)

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
