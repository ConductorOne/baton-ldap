package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"

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

func TestCreateOU(t *testing.T) {
	ctx := ctxzap.ToContext(context.Background(), zap.Must(zap.NewDevelopment()))

	l, err := createConnector(ctx, t, "")
	require.NoError(t, err)

	mkArgs := func(m map[string]interface{}) *structpb.Struct {
		s, err := structpb.NewStruct(m)
		require.NoError(t, err)
		return s
	}

	t.Run("GlobalActions registers create_ou", func(t *testing.T) {
		reg := newTestRegistry()
		require.NoError(t, l.GlobalActions(ctx, reg))
		require.Contains(t, reg.schemas, "create_ou")
	})

	t.Run("creates an OU under base-dn", func(t *testing.T) {
		rv, _, err := l.createOU(ctx, mkArgs(map[string]interface{}{"name": "engineering"}))
		require.NoError(t, err)
		require.Equal(t, "ou=engineering,dc=example,dc=org", rv.GetFields()["ou_dn"].GetStringValue())
		require.True(t, rv.GetFields()["success"].GetBoolValue())

		_, err = l.client.LdapGetRaw(ctx, "ou=engineering,dc=example,dc=org", "(objectClass=organizationalUnit)", []string{"ou"})
		require.NoError(t, err)
	})

	t.Run("is idempotent", func(t *testing.T) {
		_, _, err := l.createOU(ctx, mkArgs(map[string]interface{}{"name": "dupe"}))
		require.NoError(t, err)
		_, _, err = l.createOU(ctx, mkArgs(map[string]interface{}{"name": "dupe"}))
		require.NoError(t, err)
	})

	t.Run("sets description", func(t *testing.T) {
		_, _, err := l.createOU(ctx, mkArgs(map[string]interface{}{"name": "withdesc", "description": "My OU"}))
		require.NoError(t, err)
		e, err := l.client.LdapGetRaw(ctx, "ou=withdesc,dc=example,dc=org", "(objectClass=organizationalUnit)", []string{"description"})
		require.NoError(t, err)
		require.Equal(t, "My OU", e.GetAttributeValue("description"))
	})

	t.Run("escapes comma in name", func(t *testing.T) {
		_, _, err := l.createOU(ctx, mkArgs(map[string]interface{}{"name": "A, B"}))
		require.NoError(t, err)
		_, err = l.client.LdapGetRaw(ctx, "ou=A\\, B,dc=example,dc=org", "(objectClass=organizationalUnit)", []string{"ou"})
		require.NoError(t, err)
	})

	t.Run("rejects out-of-scope parent_dn and writes nothing", func(t *testing.T) {
		_, _, err := l.createOU(ctx, mkArgs(map[string]interface{}{"name": "x", "parent_dn": "dc=other,dc=org"}))
		require.Error(t, err)
		// Guard against a fail-open regression: the OU must not have been written.
		_, gerr := l.client.LdapGetRaw(ctx, "ou=x,dc=other,dc=org", "(objectClass=organizationalUnit)", []string{"ou"})
		require.Error(t, gerr)
	})

	t.Run("rejects empty name", func(t *testing.T) {
		_, _, err := l.createOU(ctx, mkArgs(map[string]interface{}{"name": "   "}))
		require.Error(t, err)
	})

	t.Run("conflict when DN already holds a non-OU entry", func(t *testing.T) {
		// Seed a non-OU entry at ou=conflict,dc=example,dc=org.
		// extensibleObject (auxiliary only) is rejected by the strict OpenLDAP 2.6
		// schema enforcement in this container ("no structural object class provided").
		// groupOfNames is a structural class that permits an ou RDN and is accepted.
		conflict := ldap3.NewAddRequest("ou=conflict,dc=example,dc=org", nil)
		conflict.Attribute("objectClass", []string{ldapObjectClassTop, "groupOfNames"})
		conflict.Attribute("cn", []string{"conflict"})
		conflict.Attribute("ou", []string{"conflict"})
		conflict.Attribute("member", []string{"cn=admin,dc=example,dc=org"})
		require.NoError(t, l.client.LdapAdd(ctx, conflict))

		// createOU's LdapAdd hits EntryAlreadyExists (masked to nil); verify then
		// finds the DN is not an organizationalUnit -> error.
		_, _, err := l.createOU(ctx, mkArgs(map[string]interface{}{"name": "conflict"}))
		require.Error(t, err)
	})
}

type testRegistry struct {
	schemas map[string]*v2.BatonActionSchema
}

func newTestRegistry() *testRegistry {
	return &testRegistry{schemas: map[string]*v2.BatonActionSchema{}}
}

func (r *testRegistry) Register(_ context.Context, schema *v2.BatonActionSchema, _ actions.ActionHandler) error {
	r.schemas[schema.GetName()] = schema
	return nil
}

func (r *testRegistry) RegisterAction(_ context.Context, _ string, schema *v2.BatonActionSchema, _ actions.ActionHandler) error {
	r.schemas[schema.GetName()] = schema
	return nil
}
