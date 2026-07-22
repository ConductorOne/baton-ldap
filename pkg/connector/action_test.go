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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func mustDN(t *testing.T, s string) *ldap3.DN {
	t.Helper()
	dn, err := ldap3.ParseDN(s)
	require.NoError(t, err)
	return dn
}

func entryWith(dn string, attrs map[string][]string) *ldap.Entry {
	e := &ldap3.Entry{DN: dn}
	for name, vals := range attrs {
		e.Attributes = append(e.Attributes, &ldap3.EntryAttribute{Name: name, Values: vals})
	}
	return e
}

func TestAssertDNInScope(t *testing.T) {
	scope := mustDN(t, "ou=users,dc=example,dc=org")
	tests := []struct {
		name    string
		target  string
		scope   *ldap3.DN
		wantErr bool
	}{
		{"descendant", "cn=user01,ou=users,dc=example,dc=org", scope, false},
		{"equal", "ou=users,dc=example,dc=org", scope, false},
		{"case-insensitive", "CN=User01,OU=Users,DC=Example,DC=Org", scope, false},
		{"sibling out of scope", "cn=user01,ou=admins,dc=example,dc=org", scope, true},
		{"ancestor out of scope", "dc=example,dc=org", scope, true},
		{"nil scope", "cn=user01,ou=users,dc=example,dc=org", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := assertDNInScope(mustDN(t, tt.target), tt.scope)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestResolveUpdateAttrName(t *testing.T) {
	cases := []struct {
		in       string
		wantAttr string
		wantSkip bool
	}{
		{"first_name", attrFirstName, false},
		{"last_name", attrLastName, false},
		{"display_name", attrUserDisplayName, false},
		{"user_id", attrUserUID, false},
		{"First_Name", attrFirstName, false}, // case-insensitive
		{"login", "", true},
		{"path", "", true},
		{"description", "description", false}, // raw pass-through
		{"telephoneNumber", "telephoneNumber", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			attr, skip := resolveUpdateAttrName(tc.in)
			require.Equal(t, tc.wantSkip, skip)
			if !skip {
				require.Equal(t, tc.wantAttr, attr)
			}
		})
	}
}

func TestBuildUserAttrChanges(t *testing.T) {
	dn := mustDN(t, "cn=user01,ou=users,dc=example,dc=org")
	entry := entryWith("cn=user01,ou=users,dc=example,dc=org", map[string][]string{
		"cn":          {"user01"},
		"description": {"existing"},
		"title":       {"Engineer"},
		"mail":        {"user01@example.org"},
	})

	t.Run("set new value", func(t *testing.T) {
		changes, skipped, err := buildUserAttrChanges(entry, dn,
			map[string]string{"telephoneNumber": "555-1234"}, []string{"telephoneNumber"})
		require.NoError(t, err)
		require.Empty(t, skipped)
		require.Len(t, changes, 1)
		require.Equal(t, uint(ldap3.ReplaceAttribute), changes[0].Operation)
		require.Equal(t, "telephoneNumber", changes[0].Modification.Type)
		require.Equal(t, []string{"555-1234"}, changes[0].Modification.Vals)
	})

	t.Run("clear existing attribute", func(t *testing.T) {
		changes, _, err := buildUserAttrChanges(entry, dn,
			map[string]string{"description": ""}, []string{"description"})
		require.NoError(t, err)
		require.Len(t, changes, 1)
		require.Equal(t, uint(ldap3.ReplaceAttribute), changes[0].Operation)
		require.Empty(t, changes[0].Modification.Vals)
	})

	t.Run("no-op when value already set", func(t *testing.T) {
		changes, _, err := buildUserAttrChanges(entry, dn,
			map[string]string{"title": "Engineer"}, []string{"title"})
		require.NoError(t, err)
		require.Empty(t, changes)
	})

	t.Run("no-op when clearing an absent attribute", func(t *testing.T) {
		changes, _, err := buildUserAttrChanges(entry, dn,
			map[string]string{"telephoneNumber": ""}, []string{"telephoneNumber"})
		require.NoError(t, err)
		require.Empty(t, changes)
	})

	t.Run("alias resolves to real attribute", func(t *testing.T) {
		changes, _, err := buildUserAttrChanges(entry, dn,
			map[string]string{"first_name": "Jane"}, []string{"first_name"})
		require.NoError(t, err)
		require.Len(t, changes, 1)
		require.Equal(t, attrFirstName, changes[0].Modification.Type)
	})

	t.Run("mask entry without value is skipped", func(t *testing.T) {
		changes, skipped, err := buildUserAttrChanges(entry, dn,
			map[string]string{"title": "Manager"}, []string{"title", "mail"})
		require.NoError(t, err)
		require.Equal(t, []string{"mail"}, skipped)
		require.Len(t, changes, 1)
		require.Equal(t, "title", changes[0].Modification.Type)
	})

	t.Run("synthetic keys skipped", func(t *testing.T) {
		changes, skipped, err := buildUserAttrChanges(entry, dn,
			map[string]string{"login": "x", "path": "y"}, []string{"login", "path"})
		require.NoError(t, err)
		require.Empty(t, changes)
		require.ElementsMatch(t, []string{"login", "path"}, skipped)
	})

	t.Run("RDN attribute skipped", func(t *testing.T) {
		changes, skipped, err := buildUserAttrChanges(entry, dn,
			map[string]string{"cn": "renamed"}, []string{"cn"})
		require.NoError(t, err)
		require.Empty(t, changes)
		require.Equal(t, []string{"cn"}, skipped)
	})

	t.Run("password attribute rejected", func(t *testing.T) {
		_, _, err := buildUserAttrChanges(entry, dn,
			map[string]string{"userPassword": "secret"}, []string{"userPassword"})
		require.Error(t, err)
	})

	t.Run("objectClass rejected", func(t *testing.T) {
		_, _, err := buildUserAttrChanges(entry, dn,
			map[string]string{"objectClass": "person"}, []string{"objectClass"})
		require.Error(t, err)
	})

	t.Run("duplicate resolved attr deduped", func(t *testing.T) {
		changes, skipped, err := buildUserAttrChanges(entry, dn,
			map[string]string{"user_id": "u1", "uid": "u2"}, []string{"user_id", "uid"})
		require.NoError(t, err)
		require.Len(t, changes, 1)
		require.Equal(t, attrUserUID, changes[0].Modification.Type)
		require.Equal(t, []string{"uid"}, skipped)
	})
}

func TestUpdateUserAttrs(t *testing.T) {
	ctx := ctxzap.ToContext(context.Background(), zap.Must(zap.NewDevelopment()))

	l, err := createConnector(ctx, t, "")
	require.NoError(t, err)

	mkArgs := func(dn string, attrs map[string]interface{}, mask []string) *structpb.Struct {
		maskVals := make([]interface{}, len(mask))
		for i, m := range mask {
			maskVals[i] = m
		}
		s, err := structpb.NewStruct(map[string]interface{}{
			argResourceType:    "user",
			argResourceID:      dn,
			argAttrs:           attrs,
			argAttrsUpdateMask: maskVals,
		})
		require.NoError(t, err)
		return s
	}

	const userDN = "cn=user01,ou=users,dc=example,dc=org"

	t.Run("GlobalActions registers update_user_attrs", func(t *testing.T) {
		reg := newTestRegistry()
		require.NoError(t, l.GlobalActions(ctx, reg))
		require.Contains(t, reg.schemas, "update_user_attrs")
	})

	t.Run("sets an attribute", func(t *testing.T) {
		rv, _, err := l.updateUserAttrs(ctx, mkArgs(userDN,
			map[string]interface{}{"description": "hello world"}, []string{"description"}))
		require.NoError(t, err)
		require.True(t, rv.GetFields()["success"].GetBoolValue())
		require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue())

		e, err := l.client.LdapGetRaw(ctx, userDN, "(objectClass=*)", []string{"description"})
		require.NoError(t, err)
		require.Equal(t, "hello world", e.GetAttributeValue("description"))
	})

	t.Run("is idempotent", func(t *testing.T) {
		_, _, err := l.updateUserAttrs(ctx, mkArgs(userDN,
			map[string]interface{}{"description": "same"}, []string{"description"}))
		require.NoError(t, err)
		rv, _, err := l.updateUserAttrs(ctx, mkArgs(userDN,
			map[string]interface{}{"description": "same"}, []string{"description"}))
		require.NoError(t, err)
		require.Equal(t, float64(0), rv.GetFields()["applied"].GetNumberValue())
	})

	t.Run("clears an attribute", func(t *testing.T) {
		_, _, err := l.updateUserAttrs(ctx, mkArgs(userDN,
			map[string]interface{}{"description": "temp"}, []string{"description"}))
		require.NoError(t, err)
		_, _, err = l.updateUserAttrs(ctx, mkArgs(userDN,
			map[string]interface{}{"description": ""}, []string{"description"}))
		require.NoError(t, err)
		e, err := l.client.LdapGetRaw(ctx, userDN, "(objectClass=*)", []string{"description"})
		require.NoError(t, err)
		require.Empty(t, e.GetAttributeValues("description"))
	})

	t.Run("sets multiple attributes atomically", func(t *testing.T) {
		rv, _, err := l.updateUserAttrs(ctx, mkArgs(userDN,
			map[string]interface{}{"title": "Engineer", "telephoneNumber": "555-0100"},
			[]string{"title", "telephoneNumber"}))
		require.NoError(t, err)
		require.Equal(t, float64(2), rv.GetFields()["applied"].GetNumberValue())
	})

	t.Run("mask entry with no value is skipped", func(t *testing.T) {
		rv, _, err := l.updateUserAttrs(ctx, mkArgs(userDN,
			map[string]interface{}{"title": "Lead"}, []string{"title", "mail"}))
		require.NoError(t, err)
		skipped := rv.GetFields()["skipped"].GetListValue().GetValues()
		require.Len(t, skipped, 1)
		require.Equal(t, "mail", skipped[0].GetStringValue())
	})

	t.Run("out-of-scope DN returns NotFound", func(t *testing.T) {
		_, _, err := l.updateUserAttrs(ctx, mkArgs("cn=user01,ou=other,dc=example,dc=org",
			map[string]interface{}{"description": "x"}, []string{"description"}))
		require.Error(t, err)
		require.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("missing user returns NotFound", func(t *testing.T) {
		_, _, err := l.updateUserAttrs(ctx, mkArgs("cn=ghost,ou=users,dc=example,dc=org",
			map[string]interface{}{"description": "x"}, []string{"description"}))
		require.Error(t, err)
		require.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("password attribute rejected", func(t *testing.T) {
		_, _, err := l.updateUserAttrs(ctx, mkArgs(userDN,
			map[string]interface{}{"userPassword": "secret"}, []string{"userPassword"}))
		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("RDN attribute skipped, not written", func(t *testing.T) {
		rv, _, err := l.updateUserAttrs(ctx, mkArgs(userDN,
			map[string]interface{}{"cn": "renamed"}, []string{"cn"}))
		require.NoError(t, err)
		require.Equal(t, float64(0), rv.GetFields()["applied"].GetNumberValue())
	})

	t.Run("empty mask is a no-op success", func(t *testing.T) {
		rv, _, err := l.updateUserAttrs(ctx, mkArgs(userDN,
			map[string]interface{}{"description": "x"}, []string{}))
		require.NoError(t, err)
		require.True(t, rv.GetFields()["success"].GetBoolValue())
		require.Equal(t, float64(0), rv.GetFields()["applied"].GetNumberValue())
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
