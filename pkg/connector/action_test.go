package connector

import (
	"context"
	"testing"

	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/conductorone/baton-ldap/pkg/ldap"
)

func TestBuildOUDN(t *testing.T) {
	base := func(s string) *ldap3.DN {
		dn, err := ldap3.ParseDN(s)
		require.NoError(t, err)
		return dn
	}

	tests := []struct {
		name     string
		ouName   string
		parentDN string
		baseDN   *ldap3.DN
		wantDN   string
		wantErr  bool
	}{
		{"under base", "eng", "ou=dept,dc=example,dc=org", base("dc=example,dc=org"), "ou=eng,ou=dept,dc=example,dc=org", false},
		{"equal to base", "eng", "dc=example,dc=org", base("dc=example,dc=org"), "ou=eng,dc=example,dc=org", false},
		{"empty parent defaults to base", "eng", "", base("dc=example,dc=org"), "ou=eng,dc=example,dc=org", false},
		{"whitespace parent defaults to base", "eng", "   ", base("dc=example,dc=org"), "ou=eng,dc=example,dc=org", false},
		{"comma in name is escaped", "A, B", "dc=example,dc=org", base("dc=example,dc=org"), "ou=A\\, B,dc=example,dc=org", false},
		{"fold accepts non-allowlisted attr case difference", "eng", "ou=x,businessCategory=foo,dc=org", base("businessCategory=Foo,dc=org"), "ou=eng,ou=x,businesscategory=foo,dc=org", false},
		{"out-of-scope sibling", "eng", "dc=other,dc=org", base("dc=example,dc=org"), "", true},
		{"out-of-scope ancestor", "eng", "dc=example,dc=org", base("ou=sub,dc=example,dc=org"), "", true},
		{"unparseable parent", "eng", "notadn", base("dc=example,dc=org"), "", true},
		{"empty name", "", "", base("dc=example,dc=org"), "", true},
		{"whitespace name", "   ", "", base("dc=example,dc=org"), "", true},
		{"nil base", "eng", "dc=example,dc=org", nil, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildOUDN(tt.ouName, tt.parentDN, tt.baseDN)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantDN, got)
		})
	}
}

func TestLdapGetRaw(t *testing.T) {
	ctx := ctxzap.ToContext(context.Background(), zap.Must(zap.NewDevelopment()))

	l, container, err := createConnectorWithContainer(ctx, t, "")
	require.NoError(t, err)

	// Create an OU to look up.
	addReq := ldap3.NewAddRequest("ou=rawtest,dc=example,dc=org", nil)
	addReq.Attribute("objectClass", []string{ldapObjectClassOU, ldapObjectClassTop})
	addReq.Attribute("ou", []string{"rawtest"})
	require.NoError(t, l.client.LdapAdd(ctx, addReq))

	// Build a client whose connector-wide filter EXCLUDES organizationalUnit entries.
	serverURL, err := container.ConnectionString(ctx)
	require.NoError(t, err)
	filtered, err := ldap.NewClient(ctx, serverURL, "hunter2", "cn=admin,dc=example,dc=org", false, "(objectClass=person)")
	require.NoError(t, err)

	t.Run("LdapGetRaw bypasses the connector filter", func(t *testing.T) {
		e, err := filtered.LdapGetRaw(ctx, "ou=rawtest,dc=example,dc=org", "(objectClass=organizationalUnit)", []string{"ou"})
		require.NoError(t, err)
		require.Equal(t, "rawtest", e.GetAttributeValue("ou"))
	})

	t.Run("connector filter would otherwise hide it", func(t *testing.T) {
		_, err := filtered.LdapGetWithStringDN(ctx, "ou=rawtest,dc=example,dc=org", "(objectClass=organizationalUnit)", []string{"ou"})
		require.Error(t, err)
	})

	t.Run("absent DN returns error", func(t *testing.T) {
		_, err := l.client.LdapGetRaw(ctx, "ou=ghost,dc=example,dc=org", "(objectClass=organizationalUnit)", []string{"ou"})
		require.Error(t, err)
	})

	t.Run("existing non-OU entry returns error under OU filter", func(t *testing.T) {
		// cn=user01 is seeded by the empty container as an inetOrgPerson (not an OU).
		// Under the OU filter the base search matches 0 entries -> NotFound: the
		// verify handler's "DN exists but is not an OU" conflict branch.
		_, err := l.client.LdapGetRaw(ctx, "cn=user01,ou=users,dc=example,dc=org", "(objectClass=organizationalUnit)", []string{"ou"})
		require.Error(t, err)
		// Prove the entry really exists (distinguishes this from the absent-DN case).
		e, err := l.client.LdapGetRaw(ctx, "cn=user01,ou=users,dc=example,dc=org", "(objectClass=*)", []string{"cn"})
		require.NoError(t, err)
		// Bitnami's default seed stores the display name "User1" as the cn value,
		// while the RDN component is "user01". Either way the entry was found.
		require.NotEmpty(t, e.GetAttributeValue("cn"))
	})
}
