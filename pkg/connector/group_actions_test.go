package connector

import (
	"context"
	"testing"

	"github.com/conductorone/baton-ldap/pkg/config"
	"github.com/conductorone/baton-ldap/pkg/ldap"
	"github.com/conductorone/baton-sdk/pkg/actions"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestBuildGroupDN(t *testing.T) {
	scope := mustDN(t, "ou=groups,dc=example,dc=org")

	tests := []struct {
		name      string
		groupName string
		parentDN  string
		scopeDN   *ldap3.DN
		wantDN    string
		wantErr   bool
	}{
		{"empty parent defaults to scope", "eng", "", scope, "cn=eng,ou=groups,dc=example,dc=org", false},
		{"whitespace parent defaults to scope", "eng", "   ", scope, "cn=eng,ou=groups,dc=example,dc=org", false},
		{"parent equal to scope", "eng", "ou=groups,dc=example,dc=org", scope, "cn=eng,ou=groups,dc=example,dc=org", false},
		{"parent under scope", "eng", "ou=teams,ou=groups,dc=example,dc=org", scope, "cn=eng,ou=teams,ou=groups,dc=example,dc=org", false},
		{"parent case differs from scope", "eng", "OU=Groups,DC=Example,DC=Org", scope, "cn=eng,ou=groups,dc=example,dc=org", false},
		{"name is trimmed", "  eng  ", "", scope, "cn=eng,ou=groups,dc=example,dc=org", false},
		{"comma in name is escaped", "A, B", "", scope, "cn=A\\, B,ou=groups,dc=example,dc=org", false},
		{"parent inside base but outside scope", "eng", "ou=users,dc=example,dc=org", scope, "", true},
		{"parent is an ancestor of scope", "eng", "dc=example,dc=org", scope, "", true},
		{"parent in another tree", "eng", "dc=other,dc=org", scope, "", true},
		{"unparseable parent", "eng", "notadn", scope, "", true},
		{"empty name", "", "", scope, "", true},
		{"whitespace name", "   ", "", scope, "", true},
		{"nil scope", "eng", "", nil, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildGroupDN(tt.groupName, tt.parentDN, tt.scopeDN)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantDN, got)
		})
	}
}

func TestIsGroupEntry(t *testing.T) {
	tests := []struct {
		name    string
		classes []string
		want    bool
	}{
		{"groupOfUniqueNames", []string{"top", "groupOfUniqueNames"}, true},
		{"groupOfNames lowercased by the server", []string{"top", "groupofnames"}, true},
		{"posixGroup", []string{"top", "posixGroup"}, true},
		{"AD group", []string{"top", "group"}, true},
		{"user", []string{"top", "inetOrgPerson"}, false},
		{"organizationalRole", []string{"top", "organizationalRole"}, false},
		{"no object class", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := entryWith("cn=x,ou=groups,dc=example,dc=org", map[string][]string{"objectClass": tt.classes})
			require.Equal(t, tt.want, isGroupEntry(entry))
		})
	}
}

func TestMemberAttributeForObjectClass(t *testing.T) {
	require.Equal(t, attrGroupMember, memberAttributeForObjectClass(config.CreateGroupObjectClassGroupOfNames))
	require.Equal(t, attrGroupUniqueMember, memberAttributeForObjectClass(config.CreateGroupObjectClassGroupOfUniqueNames))
}

func TestCanHoldPinnedMemberAttribute(t *testing.T) {
	tests := []struct {
		name     string
		pin      string
		required string
		classes  []string
		want     bool
	}{
		{"auto adopts any group", "", config.CreateGroupObjectClassGroupOfUniqueNames, []string{"top", "posixGroup"}, true},
		{"uniqueMember pin with groupOfUniqueNames", config.GroupMemberAttributeUniqueMember, config.CreateGroupObjectClassGroupOfUniqueNames, []string{"top", "groupofuniquenames"}, true},
		{"uniqueMember pin with posixGroup", config.GroupMemberAttributeUniqueMember, config.CreateGroupObjectClassGroupOfUniqueNames, []string{"top", "posixGroup"}, false},
		{"uniqueMember pin with groupOfNames", config.GroupMemberAttributeUniqueMember, config.CreateGroupObjectClassGroupOfUniqueNames, []string{"top", "groupOfNames"}, false},
		{"member pin with groupOfNames", config.GroupMemberAttributeMember, config.CreateGroupObjectClassGroupOfNames, []string{"top", "groupOfNames"}, true},
		{"member pin with groupOfUniqueNames", config.GroupMemberAttributeMember, config.CreateGroupObjectClassGroupOfNames, []string{"top", "groupOfUniqueNames"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := entryWith("cn=x,ou=groups,dc=example,dc=org", map[string][]string{"objectClass": tt.classes})
			require.Equal(t, tt.want, canHoldPinnedMemberAttribute(entry, tt.pin, tt.required))
		})
	}
}

func TestGlobalActionsCreateGroupRegistration(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		pin          string
		objectClass  string
		wantRegister bool
		wantErr      bool
	}{
		{"auto pin", "", "", true, false},
		{"member pin", config.GroupMemberAttributeMember, "", true, false},
		{"uniqueMember pin", config.GroupMemberAttributeUniqueMember, "", true, false},
		{"memberUid pin is not registered", config.GroupMemberAttributeMemberUID, "", false, false},
		{"conflicting class fails", config.GroupMemberAttributeMember, config.CreateGroupObjectClassGroupOfUniqueNames, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &LDAP{config: &config.Config{GroupMemberAttribute: tt.pin, CreateGroupObjectClass: tt.objectClass}}
			reg := newTestRegistry()
			err := l.GlobalActions(ctx, reg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Contains(t, reg.schemas, actionNameCreateOU)
			if tt.wantRegister {
				require.Contains(t, reg.schemas, actionNameCreateGroup)
			} else {
				require.NotContains(t, reg.schemas, actionNameCreateGroup)
			}
		})
	}
}

func TestIsPlaceholderMember(t *testing.T) {
	placeholder, err := ldap.CanonicalizeDN("cn=nobody,dc=example,dc=org")
	require.NoError(t, err)

	member := func(s string) *ldap3.DN {
		dn, err := ldap.CanonicalizeDN(s)
		require.NoError(t, err)
		return dn
	}

	configured := &groupResourceType{placeholderMember: placeholder}
	require.True(t, configured.isPlaceholderMember(member("cn=nobody,dc=example,dc=org")))
	require.True(t, configured.isPlaceholderMember(member("CN=Nobody,DC=Example,DC=Org")))
	require.False(t, configured.isPlaceholderMember(member("cn=nobody2,dc=example,dc=org")))
	require.False(t, configured.isPlaceholderMember(member("cn=nobody,ou=users,dc=example,dc=org")))

	unconfigured := &groupResourceType{}
	require.False(t, unconfigured.isPlaceholderMember(member("cn=nobody,dc=example,dc=org")))
}

const createGroupPlaceholderDN = "cn=nobody,dc=example,dc=org"

func createGroupArgs(t *testing.T, m map[string]interface{}) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	require.NoError(t, err)
	return s
}

func TestCreateGroup(t *testing.T) {
	ctx := ctxzap.ToContext(context.Background(), zap.Must(zap.NewDevelopment()))

	l, err := createConnector(ctx, t, "simple.ldif")
	require.NoError(t, err)

	setPlaceholder := func(t *testing.T, dn *ldap3.DN) {
		t.Helper()
		previous := l.config.CreateGroupPlaceholderMember
		l.config.CreateGroupPlaceholderMember = dn
		t.Cleanup(func() { l.config.CreateGroupPlaceholderMember = previous })
	}
	withPlaceholder := func(t *testing.T) {
		t.Helper()
		placeholder, err := ldap.CanonicalizeDN(createGroupPlaceholderDN)
		require.NoError(t, err)
		setPlaceholder(t, placeholder)
	}
	withoutPlaceholder := func(t *testing.T) {
		t.Helper()
		setPlaceholder(t, nil)
	}
	withPin := func(t *testing.T, pin string) {
		t.Helper()
		previous := l.config.GroupMemberAttribute
		l.config.GroupMemberAttribute = pin
		t.Cleanup(func() { l.config.GroupMemberAttribute = previous })
	}
	withObjectClass := func(t *testing.T, objectClass string) {
		t.Helper()
		previous := l.config.CreateGroupObjectClass
		l.config.CreateGroupObjectClass = objectClass
		t.Cleanup(func() { l.config.CreateGroupObjectClass = previous })
	}
	seedGroupOfUniqueNames := func(t *testing.T, name string) string {
		t.Helper()
		dn := "cn=" + name + ",ou=groups,dc=example,dc=org"
		seed := ldap3.NewAddRequest(dn, nil)
		seed.Attribute(ldapAttrObjectClass, []string{ldapObjectClassTop, config.CreateGroupObjectClassGroupOfUniqueNames})
		seed.Attribute(attrGroupCommonName, []string{name})
		seed.Attribute(attrGroupUniqueMember, []string{"cn=roger,ou=users,dc=example,dc=org"})
		require.NoError(t, l.client.LdapAdd(ctx, seed))
		return dn
	}

	t.Run("memberless add is rejected with guidance and writes nothing", func(t *testing.T) {
		withoutPlaceholder(t)

		_, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "memberless"}))
		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
		require.Contains(t, err.Error(), "create-group-placeholder-member")

		_, gerr := l.client.LdapGetRaw(ctx, "cn=memberless,ou=groups,dc=example,dc=org", ldapFilterAnyObject, nil)
		require.Error(t, gerr)
	})

	t.Run("creates a groupOfUniqueNames with the placeholder, hidden from grants", func(t *testing.T) {
		withPlaceholder(t)

		rv, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "eng", "description": "Engineering"}))
		require.NoError(t, err)
		require.True(t, rv.GetFields()["success"].GetBoolValue())
		require.True(t, rv.GetFields()[returnFieldCreated].GetBoolValue())
		require.Equal(t, "cn=eng,ou=groups,dc=example,dc=org", rv.GetFields()[returnFieldGroupDN].GetStringValue())

		e, err := l.client.LdapGetRaw(ctx, "cn=eng,ou=groups,dc=example,dc=org", ldapFilterAnyObject,
			[]string{ldapAttrObjectClass, attrGroupUniqueMember, attrGroupDescription})
		require.NoError(t, err)
		require.Contains(t, e.GetAttributeValues(ldapAttrObjectClass), config.CreateGroupObjectClassGroupOfUniqueNames)
		require.Equal(t, []string{createGroupPlaceholderDN}, e.GetAttributeValues(attrGroupUniqueMember))
		require.Equal(t, "Engineering", e.GetAttributeValue(attrGroupDescription))

		gb := l.groupSyncer()
		group := groupResourceFor(ctx, t, gb, "cn=eng,ou=groups,dc=example,dc=org")
		require.Empty(t, grantedPrincipals(ctx, t, gb, group))
	})

	t.Run("returned resource matches the one List produces", func(t *testing.T) {
		withPlaceholder(t)

		rv, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "listed", "description": "Listed"}))
		require.NoError(t, err)

		returned, ok := actions.GetResourceFieldArg(rv, returnFieldGroup)
		require.True(t, ok)

		listed := groupResourceFor(ctx, t, l.groupSyncer(), "cn=listed,ou=groups,dc=example,dc=org")
		require.Equal(t, listed.GetId().GetResource(), returned.GetId().GetResource())
		require.Equal(t, listed.GetId().GetResourceType(), returned.GetId().GetResourceType())
		require.Equal(t, listed.GetDisplayName(), returned.GetDisplayName())
		require.Equal(t, listed.GetDescription(), returned.GetDescription())
		require.Equal(t, listed.GetExternalId().GetId(), rv.GetFields()[returnFieldGroupDN].GetStringValue()) //nolint:staticcheck // ExternalId is what provisioning reads.
	})

	t.Run("adopts an existing group with created=false", func(t *testing.T) {
		withPlaceholder(t)

		rv, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "dupe"}))
		require.NoError(t, err)
		require.True(t, rv.GetFields()[returnFieldCreated].GetBoolValue())

		rv, _, err = l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "dupe"}))
		require.NoError(t, err)
		require.True(t, rv.GetFields()["success"].GetBoolValue())
		require.False(t, rv.GetFields()[returnFieldCreated].GetBoolValue())
	})

	t.Run("adopts an existing posixGroup with created=false", func(t *testing.T) {
		for _, placeholder := range []bool{true, false} {
			if placeholder {
				withPlaceholder(t)
			} else {
				withoutPlaceholder(t)
			}
			rv, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "staff"}))
			require.NoError(t, err)
			require.False(t, rv.GetFields()[returnFieldCreated].GetBoolValue())
		}
	})

	t.Run("adopts an existing group without a placeholder", func(t *testing.T) {
		withoutPlaceholder(t)
		dn := seedGroupOfUniqueNames(t, "preexisting")

		rv, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "preexisting"}))
		require.NoError(t, err)
		require.True(t, rv.GetFields()["success"].GetBoolValue())
		require.False(t, rv.GetFields()[returnFieldCreated].GetBoolValue())
		require.Equal(t, dn, rv.GetFields()[returnFieldGroupDN].GetStringValue())
	})

	t.Run("a pin refuses to adopt a group whose class cannot hold it", func(t *testing.T) {
		withPlaceholder(t)
		withPin(t, config.GroupMemberAttributeUniqueMember)
		seedGroupOfUniqueNames(t, "pinadoptable")

		_, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "staff"}))
		require.Error(t, err)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		require.Contains(t, err.Error(), config.CreateGroupObjectClassGroupOfUniqueNames)

		rv, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "pinadoptable"}))
		require.NoError(t, err)
		require.False(t, rv.GetFields()[returnFieldCreated].GetBoolValue())
	})

	t.Run("escapes a comma in the name", func(t *testing.T) {
		withPlaceholder(t)

		_, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "A, B"}))
		require.NoError(t, err)
		_, err = l.client.LdapGetRaw(ctx, "cn=A\\, B,ou=groups,dc=example,dc=org", ldapFilterAnyObject, []string{attrGroupCommonName})
		require.NoError(t, err)
	})

	t.Run("rejects a parent_dn outside group-search-dn and writes nothing", func(t *testing.T) {
		withPlaceholder(t)

		for _, parent := range []string{"ou=users,dc=example,dc=org", "dc=other,dc=org"} {
			_, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "outside", "parent_dn": parent}))
			require.Error(t, err)
			require.Equal(t, codes.InvalidArgument, status.Code(err))

			_, gerr := l.client.LdapGetRaw(ctx, "cn=outside,"+parent, ldapFilterAnyObject, nil)
			require.Error(t, gerr)
		}
	})

	t.Run("rejects an empty name", func(t *testing.T) {
		_, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "   "}))
		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("conflict when the DN holds an entry that is not a group", func(t *testing.T) {
		withPlaceholder(t)

		seed := ldap3.NewAddRequest("cn=notagroup,ou=groups,dc=example,dc=org", nil)
		seed.Attribute(ldapAttrObjectClass, []string{ldapObjectClassTop, "organizationalRole"})
		seed.Attribute(attrGroupCommonName, []string{"notagroup"})
		require.NoError(t, l.client.LdapAdd(ctx, seed))

		_, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "notagroup"}))
		require.Error(t, err)
		require.Equal(t, codes.AlreadyExists, status.Code(err))

		withoutPlaceholder(t)
		_, _, err = l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "notagroup"}))
		require.Error(t, err)
		require.Equal(t, codes.AlreadyExists, status.Code(err))
	})

	t.Run("creates a groupOfNames when configured", func(t *testing.T) {
		withPlaceholder(t)
		withObjectClass(t, config.CreateGroupObjectClassGroupOfNames)

		_, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "names"}))
		require.NoError(t, err)

		e, err := l.client.LdapGetRaw(ctx, "cn=names,ou=groups,dc=example,dc=org", ldapFilterAnyObject,
			[]string{ldapAttrObjectClass, attrGroupMember})
		require.NoError(t, err)
		require.Contains(t, e.GetAttributeValues(ldapAttrObjectClass), config.CreateGroupObjectClassGroupOfNames)
		require.Equal(t, []string{createGroupPlaceholderDN}, e.GetAttributeValues(attrGroupMember))
	})

	t.Run("a grant on a created group lands on the class attribute", func(t *testing.T) {
		withPlaceholder(t)

		_, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "provisioned"}))
		require.NoError(t, err)

		gb := l.groupSyncer()
		group := groupResourceFor(ctx, t, gb, "cn=provisioned,ou=groups,dc=example,dc=org")
		entitlement := membershipEntitlementFor(ctx, t, gb, group)
		_, err = gb.Grant(ctx, userPrincipal("cn=roger,ou=users,dc=example,dc=org"), entitlement)
		require.NoError(t, err)

		values := groupEntryValues(ctx, t, l, "cn=provisioned,ou=groups,dc=example,dc=org", attrGroupUniqueMember)
		require.ElementsMatch(t, []string{createGroupPlaceholderDN, "cn=roger,ou=users,dc=example,dc=org"}, values)
		require.Equal(t, []string{"cn=roger,ou=users,dc=example,dc=org"}, grantedPrincipals(ctx, t, gb, group))
	})

	t.Run("a grant under a member pin lands on member of a groupOfNames", func(t *testing.T) {
		withPlaceholder(t)
		withPin(t, config.GroupMemberAttributeMember)

		rv, _, err := l.createGroup(ctx, createGroupArgs(t, map[string]interface{}{"name": "pinnedmember"}))
		require.NoError(t, err)
		require.True(t, rv.GetFields()[returnFieldCreated].GetBoolValue())

		gb := l.groupSyncer()
		group := groupResourceFor(ctx, t, gb, "cn=pinnedmember,ou=groups,dc=example,dc=org")
		entitlement := membershipEntitlementFor(ctx, t, gb, group)
		_, err = gb.Grant(ctx, userPrincipal("cn=roger,ou=users,dc=example,dc=org"), entitlement)
		require.NoError(t, err)

		values := groupEntryValues(ctx, t, l, "cn=pinnedmember,ou=groups,dc=example,dc=org", attrGroupMember)
		require.ElementsMatch(t, []string{createGroupPlaceholderDN, "cn=roger,ou=users,dc=example,dc=org"}, values)
		require.Equal(t, []string{"cn=roger,ou=users,dc=example,dc=org"}, grantedPrincipals(ctx, t, gb, group))
	})
}
