package connector

import (
	"context"
	"errors"
	"fmt"
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

// testActionName is an arbitrary action name used only to exercise
// buildUserAttrChanges' actionName parameter (it varies error-message text,
// never behavior); it is not tied to any real registered action.
const testActionName = "test_action"

func TestBuildUserAttrChanges(t *testing.T) {
	dn := mustDN(t, "cn=user01,ou=users,dc=example,dc=org")
	entry := entryWith("cn=user01,ou=users,dc=example,dc=org", map[string][]string{
		"cn":           {"user01"},
		"description":  {"existing"},
		"title":        {"Engineer"},
		"mail":         {"user01@example.org"},
		"otherMailbox": {"alt1@example.org", "alt2@example.org"},
	})

	t.Run("set new value", func(t *testing.T) {
		changes, skipped, err := buildUserAttrChanges(entry, dn,
			map[string]string{"telephoneNumber": "555-1234"}, []string{"telephoneNumber"}, testActionName)
		require.NoError(t, err)
		require.Empty(t, skipped)
		require.Len(t, changes, 1)
		require.Equal(t, uint(ldap3.ReplaceAttribute), changes[0].Operation)
		require.Equal(t, "telephoneNumber", changes[0].Modification.Type)
		require.Equal(t, []string{"555-1234"}, changes[0].Modification.Vals)
	})

	t.Run("clear existing attribute", func(t *testing.T) {
		changes, _, err := buildUserAttrChanges(entry, dn,
			map[string]string{"description": ""}, []string{"description"}, testActionName)
		require.NoError(t, err)
		require.Len(t, changes, 1)
		require.Equal(t, uint(ldap3.ReplaceAttribute), changes[0].Operation)
		require.Empty(t, changes[0].Modification.Vals)
	})

	t.Run("no-op when value already set", func(t *testing.T) {
		changes, _, err := buildUserAttrChanges(entry, dn,
			map[string]string{"title": "Engineer"}, []string{"title"}, testActionName)
		require.NoError(t, err)
		require.Empty(t, changes)
	})

	t.Run("no-op when clearing an absent attribute", func(t *testing.T) {
		changes, _, err := buildUserAttrChanges(entry, dn,
			map[string]string{"telephoneNumber": ""}, []string{"telephoneNumber"}, testActionName)
		require.NoError(t, err)
		require.Empty(t, changes)
	})

	t.Run("mask entries are written verbatim, never alias-resolved", func(t *testing.T) {
		// Regression guard for the custom_attributes aliasing bug: this function
		// used to run every mask entry through an alias table, so a caller's raw
		// attribute name could be silently redirected to a different real
		// attribute ("user_id" -> uid, "first_name" -> givenName). Resolving
		// public field names is now buildProfileUpdate's job; here a mask entry
		// IS the attribute name, whatever it looks like.
		for _, name := range []string{"user_id", "first_name", "email"} {
			t.Run(name, func(t *testing.T) {
				changes, skipped, err := buildUserAttrChanges(entry, dn,
					map[string]string{name: "v"}, []string{name}, testActionName)
				require.NoError(t, err)
				require.Empty(t, skipped)
				require.Len(t, changes, 1)
				require.Equal(t, name, changes[0].Modification.Type)
				require.Equal(t, []string{"v"}, changes[0].Modification.Vals)
			})
		}
	})

	t.Run("mask entry without value is skipped", func(t *testing.T) {
		changes, skipped, err := buildUserAttrChanges(entry, dn,
			map[string]string{"title": "Manager"}, []string{"title", "mail"}, testActionName)
		require.NoError(t, err)
		require.Equal(t, []string{"mail"}, skipped)
		require.Len(t, changes, 1)
		require.Equal(t, "title", changes[0].Modification.Type)
	})

	t.Run("baton's synthetic profile keys are no longer special-cased", func(t *testing.T) {
		// "login" and "path" are baton profile keys, not LDAP attributes, and
		// used to be silently dropped from any mask. They were only ever
		// reachable from a caller that passed a baton-profile-shaped mask; the
		// only caller left builds its mask from raw LDAP attribute names, where
		// these two mean nothing more than the literal attributes so named.
		// Skipping them would be the same class of silent misbehavior as the
		// alias redirect above, so they are attempted and left for the server to
		// reject (undefinedAttributeType) if the directory has no such attribute.
		changes, skipped, err := buildUserAttrChanges(entry, dn,
			map[string]string{"login": "x", "path": "y"}, []string{"login", "path"}, testActionName)
		require.NoError(t, err)
		require.Empty(t, skipped)
		require.Len(t, changes, 2)
		require.Equal(t, "login", changes[0].Modification.Type)
		require.Equal(t, []string{"x"}, changes[0].Modification.Vals)
		require.Equal(t, "path", changes[1].Modification.Type)
		require.Equal(t, []string{"y"}, changes[1].Modification.Vals)
	})

	t.Run("RDN attribute skipped", func(t *testing.T) {
		changes, skipped, err := buildUserAttrChanges(entry, dn,
			map[string]string{"cn": "renamed"}, []string{"cn"}, testActionName)
		require.NoError(t, err)
		require.Empty(t, changes)
		require.Equal(t, []string{"cn"}, skipped)
	})

	t.Run("password attribute rejected", func(t *testing.T) {
		_, _, err := buildUserAttrChanges(entry, dn,
			map[string]string{"userPassword": "secret"}, []string{"userPassword"}, testActionName)
		require.Error(t, err)
	})

	t.Run("objectClass rejected", func(t *testing.T) {
		_, _, err := buildUserAttrChanges(entry, dn,
			map[string]string{"objectClass": "person"}, []string{"objectClass"}, testActionName)
		require.Error(t, err)
	})

	t.Run("denylist error message names the calling action, not a hardcoded one", func(t *testing.T) {
		// R1: buildUserAttrChanges must not hardcode any specific action name in
		// its denylist error messages -- a caller like update_profile passes its
		// own actionName so the customer sees the right action name. Proven by
		// varying actionName across two calls and checking the error tracks
		// whichever one was actually passed, not by checking for the mere
		// absence of an unrelated, never-supplied string.
		_, _, err := buildUserAttrChanges(entry, dn,
			map[string]string{"userPassword": "secret"}, []string{"userPassword"}, "update_profile")
		require.Error(t, err)
		require.Contains(t, err.Error(), "update_profile")
		require.NotContains(t, err.Error(), testActionName)

		_, _, err = buildUserAttrChanges(entry, dn,
			map[string]string{"userPassword": "secret"}, []string{"userPassword"}, testActionName)
		require.Error(t, err)
		require.Contains(t, err.Error(), testActionName)
		require.NotContains(t, err.Error(), "update_profile")
	})

	t.Run("two mask entries naming the same attribute are deduped, first wins", func(t *testing.T) {
		// LDAP attribute names are case-insensitive, so these are one attribute.
		// The first surviving entry claims it; the second is reported skipped
		// rather than issuing a second, conflicting Replace for the same type.
		//
		// (The dedupe's "seen is only marked after the earlier gates" ordering --
		// so an entry skipped for a missing value cannot shadow a later entry for
		// the same attribute -- is no longer separately observable: with literal
		// attribute names, two entries naming the same attribute always fold to
		// the same key in attrs' case-insensitive index, so either both find a
		// value or neither does.)
		changes, skipped, err := buildUserAttrChanges(entry, dn,
			map[string]string{"telephoneNumber": "555-1111", "TelephoneNumber": "555-2222"},
			[]string{"telephoneNumber", "TelephoneNumber"}, testActionName)
		require.NoError(t, err)
		require.Len(t, changes, 1)
		require.Equal(t, "telephoneNumber", changes[0].Modification.Type)
		require.Equal(t, []string{"555-1111"}, changes[0].Modification.Vals)
		require.Equal(t, []string{"TelephoneNumber"}, skipped)
	})

	t.Run("case-insensitive attrs lookup falls back when mask/attrs key case differs", func(t *testing.T) {
		// Bug #3: attrs is keyed by "TelephoneNumber" but the mask entry (and the
		// resolved LDAP attribute name) is "telephoneNumber" -- an exact map
		// lookup would miss this; the case-insensitive fallback must catch it.
		changes, skipped, err := buildUserAttrChanges(entry, dn,
			map[string]string{"TelephoneNumber": "555-2000"}, []string{"telephoneNumber"}, testActionName)
		require.NoError(t, err)
		require.Empty(t, skipped)
		require.Len(t, changes, 1)
		require.Equal(t, []string{"555-2000"}, changes[0].Modification.Vals)
	})

	t.Run("exact-case attrs key wins over the case-insensitive fallback", func(t *testing.T) {
		changes, _, err := buildUserAttrChanges(entry, dn,
			map[string]string{"description": "exact", "Description": "fallback"}, []string{"description"}, testActionName)
		require.NoError(t, err)
		require.Len(t, changes, 1)
		require.Equal(t, []string{"exact"}, changes[0].Modification.Vals)
	})

	t.Run("setting a non-empty value on a multi-valued attribute is a hard error", func(t *testing.T) {
		// Bug #2 fix: buildUserAttrChanges previously collapsed a multi-valued
		// attribute down to the single supplied value, silently discarding every
		// other existing value with success:true and no signal to the caller.
		// That pinning test documented the bug deliberately so a future fix
		// would be a reviewed change, not an accidental side effect -- this is
		// that fix. Setting a specific non-empty value must now abort the whole
		// batch instead of collapsing.
		changes, skipped, err := buildUserAttrChanges(entry, dn,
			map[string]string{"otherMailbox": "new@example.org"}, []string{"otherMailbox"}, testActionName)
		require.Error(t, err)
		require.Nil(t, changes)
		require.Nil(t, skipped)
		require.Contains(t, err.Error(), "otherMailbox")
		require.Contains(t, err.Error(), "2")
		require.Contains(t, err.Error(), testActionName)
	})

	t.Run("multi-valued attribute error message names the calling action, not a hardcoded one", func(t *testing.T) {
		// Proven by varying actionName across two calls and checking the error
		// tracks whichever one was actually passed, not by checking for the
		// mere absence of an unrelated, never-supplied string.
		_, _, err := buildUserAttrChanges(entry, dn,
			map[string]string{"otherMailbox": "new@example.org"}, []string{"otherMailbox"}, "update_profile")
		require.Error(t, err)
		require.Contains(t, err.Error(), "update_profile")
		require.NotContains(t, err.Error(), testActionName)

		_, _, err = buildUserAttrChanges(entry, dn,
			map[string]string{"otherMailbox": "new@example.org"}, []string{"otherMailbox"}, testActionName)
		require.Error(t, err)
		require.Contains(t, err.Error(), testActionName)
		require.NotContains(t, err.Error(), "update_profile")
	})

	t.Run("clearing a multi-valued attribute is not data loss and still succeeds", func(t *testing.T) {
		// The nuance: an empty value is an explicit, intentional "remove all
		// values" operation (LDAP Replace with no values), regardless of how
		// many values the attribute currently holds. Only setting a specific
		// non-empty value on a multi-valued attribute is refused.
		changes, skipped, err := buildUserAttrChanges(entry, dn,
			map[string]string{"otherMailbox": ""}, []string{"otherMailbox"}, testActionName)
		require.NoError(t, err)
		require.Empty(t, skipped)
		require.Len(t, changes, 1)
		require.Equal(t, uint(ldap3.ReplaceAttribute), changes[0].Operation)
		require.Equal(t, "otherMailbox", changes[0].Modification.Type)
		require.Empty(t, changes[0].Modification.Vals)
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

// TestLookupErrToGRPC pins the discrimination applyUserAttrUpdate depends on:
// only a confirmed zero-result read may become NotFound. The error shapes below
// are the ones pkg/ldap actually produces (see LdapGetWithStringDN and
// _ldapSearch), each wrapped the way getAccount wraps them.
func TestLookupErrToGRPC(t *testing.T) {
	// getAccount's wrapper. Every error reaching lookupErrToGRPC has been through it.
	wrap := func(err error) error {
		return fmt.Errorf("ldap-connector: failed to get user: %w", err)
	}
	notFoundStatus := status.Errorf(codes.NotFound, "baton-ldap: no such object")

	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"nil", nil, codes.OK},

		// Genuinely absent. Two shapes: the client's own zero-results synthesis,
		// and the server answering noSuchObject (joined with the same status).
		{"zero results", wrap(notFoundStatus), codes.NotFound},
		{"bare zero results", notFoundStatus, codes.NotFound},
		{
			"server no such object",
			wrap(errors.Join(notFoundStatus, ldap3.NewError(ldap3.LDAPResultNoSuchObject, errors.New("gone")))),
			codes.NotFound,
		},

		// Directory data-integrity problem: the user exists twice. Must not be
		// NotFound, and must not look retryable.
		{
			"multiple entries",
			wrap(fmt.Errorf("%w: %s", ldap.ErrMultipleEntries, "uid=dupe,ou=users,dc=example,dc=com")),
			codes.Internal,
		},

		// Transport failures. The connector already exhausted its retries, but the
		// condition is still transient, not a missing user.
		{"network result code", wrap(ldap3.NewError(ldap3.ErrorNetwork, errors.New("conn reset"))), codes.Unavailable},
		{"truncated response", wrap(errors.New("unable to read LDAP response packet: EOF")), codes.Unavailable},

		// Bind/permission failures against the directory, not a caller mistake.
		{"invalid credentials", wrap(ldap3.NewError(ldap3.LDAPResultInvalidCredentials, errors.New("bad bind"))), codes.Unauthenticated},
		{"insufficient access", wrap(ldap3.NewError(ldap3.LDAPResultInsufficientAccessRights, errors.New("denied"))), codes.PermissionDenied},
		{"admin limit", wrap(ldap3.NewError(ldap3.LDAPResultAdminLimitExceeded, errors.New("limit"))), codes.ResourceExhausted},
		{"unwilling to perform", wrap(ldap3.NewError(ldap3.LDAPResultUnwillingToPerform, errors.New("policy"))), codes.FailedPrecondition},

		// Context errors come from the connection pool, not from LDAP.
		{"canceled", wrap(context.Canceled), codes.Canceled},
		{"deadline exceeded", wrap(context.DeadlineExceeded), codes.DeadlineExceeded},

		// Unclassifiable errors keep the package's pre-existing Unknown, rather
		// than being guessed into a retryable or terminal bucket.
		{"unmapped ldap code", wrap(ldap3.NewError(ldap3.LDAPResultLoopDetect, errors.New("loop"))), codes.Unknown},
		{"non-ldap error", wrap(errors.New("boom")), codes.Unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, lookupErrToGRPC(tc.err))
		})
	}

	// The regression this function exists to prevent: every non-absent failure
	// used to be reported as NotFound.
	t.Run("only absence is NotFound", func(t *testing.T) {
		for _, err := range []error{
			wrap(fmt.Errorf("%w: %s", ldap.ErrMultipleEntries, "uid=dupe,dc=example,dc=com")),
			wrap(ldap3.NewError(ldap3.ErrorNetwork, errors.New("conn reset"))),
			wrap(ldap3.NewError(ldap3.LDAPResultInvalidCredentials, errors.New("bad bind"))),
			wrap(ldap3.NewError(ldap3.LDAPResultInsufficientAccessRights, errors.New("denied"))),
			wrap(errors.New("boom")),
		} {
			require.NotEqual(t, codes.NotFound, lookupErrToGRPC(err), "err: %v", err)
		}
	})
}

func TestLdapResultCodeToGRPC(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		// Transient.
		{"busy", ldap3.NewError(ldap3.LDAPResultBusy, errors.New("busy")), codes.Unavailable},
		{"unavailable", ldap3.NewError(ldap3.LDAPResultUnavailable, errors.New("down")), codes.Unavailable},
		{"network", ldap3.NewError(ldap3.ErrorNetwork, errors.New("conn reset")), codes.Unavailable},
		{"time limit", ldap3.NewError(ldap3.LDAPResultTimeLimitExceeded, errors.New("slow")), codes.DeadlineExceeded},

		// Server-imposed limits.
		{"admin limit", ldap3.NewError(ldap3.LDAPResultAdminLimitExceeded, errors.New("limit")), codes.ResourceExhausted},
		{"size limit", ldap3.NewError(ldap3.LDAPResultSizeLimitExceeded, errors.New("limit")), codes.ResourceExhausted},

		// Terminal.
		{"insufficient access", ldap3.NewError(ldap3.LDAPResultInsufficientAccessRights, errors.New("denied")), codes.PermissionDenied},
		{"invalid credentials", ldap3.NewError(ldap3.LDAPResultInvalidCredentials, errors.New("bad bind")), codes.Unauthenticated},
		{"no such object", ldap3.NewError(ldap3.LDAPResultNoSuchObject, errors.New("gone")), codes.NotFound},
		{"object class violation", ldap3.NewError(ldap3.LDAPResultObjectClassViolation, errors.New("schema")), codes.InvalidArgument},
		{"constraint violation", ldap3.NewError(ldap3.LDAPResultConstraintViolation, errors.New("constraint")), codes.InvalidArgument},
		{"not allowed on rdn", ldap3.NewError(ldap3.LDAPResultNotAllowedOnRDN, errors.New("rdn")), codes.InvalidArgument},
		{"unwilling to perform", ldap3.NewError(ldap3.LDAPResultUnwillingToPerform, errors.New("read-only")), codes.FailedPrecondition},

		// Fallbacks: an unmapped LDAP result code, a non-LDAP error, and nil all
		// keep the package's pre-existing codes.Unknown classification.
		{"unmapped ldap code", ldap3.NewError(ldap3.LDAPResultLoopDetect, errors.New("loop")), codes.Unknown},
		{"non-ldap error", errors.New("boom"), codes.Unknown},
		{"nil error", nil, codes.Unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ldapResultCodeToGRPC(tc.err))
		})
	}

	// The result code must survive being wrapped, since applyUserAttrUpdate maps
	// whatever the client layer hands back rather than a bare *ldap3.Error.
	t.Run("wrapped error", func(t *testing.T) {
		wrapped := fmt.Errorf("modify failed: %w", ldap3.NewError(ldap3.LDAPResultBusy, errors.New("busy")))
		require.Equal(t, codes.Unavailable, ldapResultCodeToGRPC(wrapped))
	})
}
