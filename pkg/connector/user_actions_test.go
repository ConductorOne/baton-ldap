package connector

import (
	"context"
	"testing"

	config_sdk "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// mkProfileArgs builds an update_profile args struct from a flat map. Nested
// maps (e.g. "custom_attributes") are converted to nested structs by
// structpb.NewStruct.
func mkProfileArgs(t *testing.T, m map[string]interface{}) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	require.NoError(t, err)
	return s
}

// mkUpdateProfileArgs builds a full update_profile args struct, including the
// user_id ResourceIdField wire shape actions.GetResourceIDArg expects: a
// nested struct with resource_id (+ optional resource_type_id).
func mkUpdateProfileArgs(t *testing.T, userDN, resourceType string, fields map[string]interface{}) *structpb.Struct {
	t.Helper()
	m := map[string]interface{}{}
	for k, v := range fields {
		m[k] = v
	}
	userID := map[string]interface{}{
		"resource_id": userDN,
	}
	if resourceType != "" {
		userID["resource_type_id"] = resourceType
	}
	m[argUserID] = userID
	return mkProfileArgs(t, m)
}

func TestBuildProfileUpdate(t *testing.T) {
	t.Run("all four named fields resolve to their real LDAP attributes", func(t *testing.T) {
		args := mkProfileArgs(t, map[string]interface{}{
			"first_name":   "Jane",
			"last_name":    "Doe",
			"display_name": "Jane Doe",
			"email":        "jane@example.org",
		})
		attrs, mask, skipped, err := buildProfileUpdate(args)
		require.NoError(t, err)
		require.Empty(t, skipped)
		require.Equal(t, []string{attrFirstName, attrLastName, attrUserDisplayName, attrUserMail}, mask)
		require.Equal(t, map[string]string{
			attrFirstName:       "Jane",
			attrLastName:        "Doe",
			attrUserDisplayName: "Jane Doe",
			attrUserMail:        "jane@example.org",
		}, attrs)
	})

	t.Run("named field present-but-empty is dropped and reported in skipped under its ARGUMENT name", func(t *testing.T) {
		args := mkProfileArgs(t, map[string]interface{}{
			"first_name": "",
			"last_name":  "Doe",
		})
		attrs, mask, skipped, err := buildProfileUpdate(args)
		require.NoError(t, err)
		// The caller typed "first_name", not "givenName" -- report back what
		// they supplied even though the mask now carries resolved attributes.
		require.Equal(t, []string{"first_name"}, skipped)
		require.Equal(t, []string{attrLastName}, mask)
		require.Equal(t, map[string]string{attrLastName: "Doe"}, attrs)
	})

	t.Run("named field absent is neither masked nor skipped", func(t *testing.T) {
		args := mkProfileArgs(t, map[string]interface{}{
			"last_name": "Doe",
		})
		attrs, mask, skipped, err := buildProfileUpdate(args)
		require.NoError(t, err)
		require.Empty(t, skipped)
		require.Equal(t, []string{attrLastName}, mask)
		require.Equal(t, map[string]string{attrLastName: "Doe"}, attrs)
	})

	t.Run("custom_attributes only, mask sorted ascending", func(t *testing.T) {
		args := mkProfileArgs(t, map[string]interface{}{
			"custom_attributes": map[string]interface{}{
				"title":           "Engineer",
				"telephoneNumber": "555-1234",
				"description":     "hi",
			},
		})
		attrs, mask, skipped, err := buildProfileUpdate(args)
		require.NoError(t, err)
		require.Empty(t, skipped)
		require.Equal(t, []string{"description", "telephoneNumber", "title"}, mask)
		require.Equal(t, map[string]string{
			"title":           "Engineer",
			"telephoneNumber": "555-1234",
			"description":     "hi",
		}, attrs)
	})

	t.Run("custom_attributes empty value is kept in the mask (clears, unlike a named field)", func(t *testing.T) {
		args := mkProfileArgs(t, map[string]interface{}{
			"custom_attributes": map[string]interface{}{
				"description": "",
			},
		})
		attrs, mask, skipped, err := buildProfileUpdate(args)
		require.NoError(t, err)
		require.Empty(t, skipped)
		require.Equal(t, []string{"description"}, mask)
		require.Equal(t, map[string]string{"description": ""}, attrs)
	})

	t.Run("custom_attributes key colliding with a named field is dropped and reported once (R3)", func(t *testing.T) {
		args := mkProfileArgs(t, map[string]interface{}{
			"first_name": "Jane",
			"custom_attributes": map[string]interface{}{
				"First_Name": "Bob", // case-insensitive collision with the named arg
				"title":      "Engineer",
			},
		})
		attrs, mask, skipped, err := buildProfileUpdate(args)
		require.NoError(t, err)
		require.Equal(t, []string{"First_Name"}, skipped)
		require.Equal(t, []string{attrFirstName, "title"}, mask)
		require.Equal(t, map[string]string{attrFirstName: "Jane", "title": "Engineer"}, attrs)
	})

	t.Run("custom_attributes key colliding with a named field's resolved attribute is dropped (R3)", func(t *testing.T) {
		// first_name claims givenName, so a raw "givenName" custom entry would
		// land on the same attrs key and silently clobber it. Named field wins;
		// the custom entry is reported under the key the caller typed.
		args := mkProfileArgs(t, map[string]interface{}{
			"first_name": "Jane",
			"custom_attributes": map[string]interface{}{
				"GIVENNAME": "Bob", // case-insensitive collision with givenName
				"title":     "Engineer",
			},
		})
		attrs, mask, skipped, err := buildProfileUpdate(args)
		require.NoError(t, err)
		require.Equal(t, []string{"GIVENNAME"}, skipped)
		require.Equal(t, []string{attrFirstName, "title"}, mask)
		require.Equal(t, map[string]string{attrFirstName: "Jane", "title": "Engineer"}, attrs)
	})

	t.Run("custom_attributes may write a named field's attribute directly when that field claimed no slot", func(t *testing.T) {
		// Only an actually-claimed slot collides. givenName is a perfectly
		// ordinary raw attribute name when first_name is absent (or present-but-
		// empty, and therefore dropped) -- refusing it would be the connector
		// second-guessing a documented raw attribute name.
		for name, fields := range map[string]map[string]interface{}{
			"first_name absent": {
				"custom_attributes": map[string]interface{}{attrFirstName: "Bob"},
			},
			"first_name present-but-empty": {
				"first_name":        "",
				"custom_attributes": map[string]interface{}{attrFirstName: "Bob"},
			},
		} {
			t.Run(name, func(t *testing.T) {
				attrs, mask, _, err := buildProfileUpdate(mkProfileArgs(t, fields))
				require.NoError(t, err)
				require.Equal(t, []string{attrFirstName}, mask)
				require.Equal(t, map[string]string{attrFirstName: "Bob"}, attrs)
			})
		}
	})

	t.Run("custom_attributes user_id is a literal attribute name, never aliased to uid", func(t *testing.T) {
		// The bug: "user_id" used to resolve through the named-field alias table
		// on its way to the modify, so this wrote the uid attribute instead --
		// a different real attribute than the caller named, with no error and no
		// entry in skipped.
		args := mkProfileArgs(t, map[string]interface{}{
			"custom_attributes": map[string]interface{}{"user_id": "somevalue"},
		})
		attrs, mask, skipped, err := buildProfileUpdate(args)
		require.NoError(t, err)
		require.Empty(t, skipped)
		require.Equal(t, []string{"user_id"}, mask)
		require.Equal(t, map[string]string{"user_id": "somevalue"}, attrs)
		require.NotContains(t, attrs, attrUserUID, "user_id must not be redirected to the uid attribute")
	})

	t.Run("custom_attributes login and path are literal attribute names, not skipped synthetic keys", func(t *testing.T) {
		// baton's synthetic profile keys are no longer special-cased in this
		// path: they reach the server as raw attribute names and are rejected
		// there if undefined, rather than being silently dropped by us.
		args := mkProfileArgs(t, map[string]interface{}{
			"custom_attributes": map[string]interface{}{"login": "x", schemaFieldPath: "y"},
		})
		attrs, mask, skipped, err := buildProfileUpdate(args)
		require.NoError(t, err)
		require.Empty(t, skipped)
		require.Equal(t, []string{"login", schemaFieldPath}, mask)
		require.Equal(t, map[string]string{"login": "x", schemaFieldPath: "y"}, attrs)
	})

	t.Run("custom_attributes collision is dropped even when the named field itself is absent", func(t *testing.T) {
		// R3 protects the reserved name, not just an active value collision.
		args := mkProfileArgs(t, map[string]interface{}{
			"custom_attributes": map[string]interface{}{
				"email": "raw@example.org",
			},
		})
		attrs, mask, skipped, err := buildProfileUpdate(args)
		require.NoError(t, err)
		require.Equal(t, []string{"email"}, skipped)
		require.Empty(t, mask)
		require.Empty(t, attrs)
	})

	t.Run("combined named + custom_attributes: named first, then sorted custom", func(t *testing.T) {
		args := mkProfileArgs(t, map[string]interface{}{
			"first_name": "Jane",
			"email":      "jane@example.org",
			"custom_attributes": map[string]interface{}{
				"zzz": "1",
				"aaa": "2",
			},
		})
		_, mask, skipped, err := buildProfileUpdate(args)
		require.NoError(t, err)
		require.Empty(t, skipped)
		require.Equal(t, []string{attrFirstName, attrUserMail, "aaa", "zzz"}, mask)
	})

	t.Run("wrong-typed named field errors loudly", func(t *testing.T) {
		args := mkProfileArgs(t, map[string]interface{}{
			"first_name": true,
		})
		_, _, _, err := buildProfileUpdate(args)
		require.Error(t, err)
	})

	t.Run("wrong-typed custom_attributes entry value errors loudly", func(t *testing.T) {
		args := mkProfileArgs(t, map[string]interface{}{
			"custom_attributes": map[string]interface{}{
				"title": 42.0,
			},
		})
		_, _, _, err := buildProfileUpdate(args)
		require.Error(t, err)
	})

	t.Run("wrong-typed custom_attributes container errors loudly", func(t *testing.T) {
		args := mkProfileArgs(t, map[string]interface{}{
			"custom_attributes": "not a struct",
		})
		_, _, _, err := buildProfileUpdate(args)
		require.Error(t, err)
	})

	t.Run("empty args is a no-op with nothing masked or skipped", func(t *testing.T) {
		args := mkProfileArgs(t, map[string]interface{}{})
		attrs, mask, skipped, err := buildProfileUpdate(args)
		require.NoError(t, err)
		require.Empty(t, attrs)
		require.Empty(t, mask)
		require.Empty(t, skipped)
	})

	t.Run("deterministic mask order is stable across repeated calls (map iteration is randomized)", func(t *testing.T) {
		args := mkProfileArgs(t, map[string]interface{}{
			"first_name": "Jane",
			"custom_attributes": map[string]interface{}{
				"m": "1", "z": "2", "a": "3", "q": "4", "b": "5", "y": "6",
			},
		})
		var first []string
		for i := 0; i < 25; i++ {
			_, mask, _, err := buildProfileUpdate(args)
			require.NoError(t, err)
			if first == nil {
				first = mask
			} else {
				require.Equal(t, first, mask, "mask order must be stable across repeated calls despite map iteration randomization")
			}
		}
		require.Equal(t, []string{attrFirstName, "a", "b", "m", "q", "y", "z"}, first)
	})
}

func TestUpdateProfileActionSchema(t *testing.T) {
	schema := updateProfileActionSchema()

	require.Equal(t, actionNameUpdateProfile, schema.GetName())
	require.Equal(t, []v2.ActionType{v2.ActionType_ACTION_TYPE_ACCOUNT_UPDATE_PROFILE}, schema.GetActionType())
	require.Empty(t, schema.GetResourceTypeId(), "ResourceTypeId must be unset in the literal -- RegisterResourceAction stamps it")

	var userIDArg, customAttrsArg *config_sdk.Field
	namedSeen := map[string]bool{}
	for _, arg := range schema.GetArguments() {
		switch arg.GetName() {
		case argUserID:
			userIDArg = arg
		case argCustomAttributes:
			customAttrsArg = arg
		case argFirstName, argLastName, argDisplayName, argEmail:
			namedSeen[arg.GetName()] = true
			require.NotNilf(t, arg.GetStringField(), "%s must be a StringField", arg.GetName())
		}
	}

	require.NotNil(t, userIDArg, "user_id argument must be present")
	require.True(t, userIDArg.GetIsRequired())
	require.NotNil(t, userIDArg.GetResourceIdField())
	require.Contains(t, userIDArg.GetResourceIdField().GetRules().GetAllowedResourceTypeIds(), resourceTypeUser.Id)

	require.NotNil(t, customAttrsArg, "custom_attributes argument must be present")
	require.NotNil(t, customAttrsArg.GetStringMapField())

	require.Len(t, namedSeen, 4, "all 4 named fields must be present as StringField arguments")

	// Regression guard: updateProfileActionSchema must build a fresh struct on
	// every call, not return a shared package-level var. RegisterResourceAction
	// mutates ResourceTypeId in place on registration; a shared value would leak
	// that mutation to every other holder of the same pointer.
	schema2 := updateProfileActionSchema()
	require.NotSame(t, schema, schema2)
	schema.SetResourceTypeId(resourceTypeUser.Id)
	require.Empty(t, schema2.GetResourceTypeId(), "mutating one schema instance must not affect another")
}

// TestUpdateProfile exercises the update_profile handler end to end against a
// real (containerized) OpenLDAP server. It requires Docker and is not
// runnable in a sandbox without it; it is included here so the handler is
// covered as soon as Docker is available, and so it is compile-checked by
// `go vet`/`go build` even when it can't be executed.
func TestUpdateProfile(t *testing.T) {
	ctx := ctxzap.ToContext(context.Background(), zap.Must(zap.NewDevelopment()))

	l, err := createConnector(ctx, t, "")
	require.NoError(t, err)

	ub := userBuilder(l.client, l.config.UserSearchDN, l.config.DisableOperationalAttrs)

	const userDN = "cn=user01,ou=users,dc=example,dc=org"

	t.Run("ResourceActions registers update_profile", func(t *testing.T) {
		reg := newTestRegistry()
		require.NoError(t, ub.ResourceActions(ctx, reg))
		require.Contains(t, reg.schemas, actionNameUpdateProfile)
	})

	t.Run("sets first_name", func(t *testing.T) {
		rv, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"first_name": "Jane",
		}))
		require.NoError(t, err)
		require.True(t, rv.GetFields()["success"].GetBoolValue())
		require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue())
	})

	t.Run("sets last_name", func(t *testing.T) {
		rv, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"last_name": "Doe",
		}))
		require.NoError(t, err)
		require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue())
	})

	t.Run("sets display_name", func(t *testing.T) {
		rv, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"display_name": "Jane Doe",
		}))
		require.NoError(t, err)
		require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue())
	})

	t.Run("sets email, aliased to the mail attribute", func(t *testing.T) {
		rv, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"email": "jane.doe@example.org",
		}))
		require.NoError(t, err)
		require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue())

		e, err := l.client.LdapGetRaw(ctx, userDN, "(objectClass=*)", []string{attrUserMail})
		require.NoError(t, err)
		require.Equal(t, "jane.doe@example.org", e.GetAttributeValue(attrUserMail))
	})

	t.Run("sets a custom_attributes entry", func(t *testing.T) {
		rv, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"custom_attributes": map[string]interface{}{"title": "Engineer"},
		}))
		require.NoError(t, err)
		require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue())
	})

	t.Run("combined named fields and custom_attributes apply together", func(t *testing.T) {
		rv, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"first_name": "Combo",
			"custom_attributes": map[string]interface{}{
				"telephoneNumber": "555-0100",
			},
		}))
		require.NoError(t, err)
		require.Equal(t, float64(2), rv.GetFields()["applied"].GetNumberValue())
	})

	t.Run("is idempotent: re-running the same update applies nothing the second time", func(t *testing.T) {
		args := mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"custom_attributes": map[string]interface{}{"title": "Staff Engineer"},
		})
		_, _, err := ub.updateProfile(ctx, args)
		require.NoError(t, err)
		rv, _, err := ub.updateProfile(ctx, args)
		require.NoError(t, err)
		require.Equal(t, float64(0), rv.GetFields()["applied"].GetNumberValue())
	})

	t.Run("empty named field is a no-op, not a clear, and is reported in skipped", func(t *testing.T) {
		rv, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"first_name": "",
		}))
		require.NoError(t, err)
		require.Equal(t, float64(0), rv.GetFields()["applied"].GetNumberValue())
		skipped := rv.GetFields()["skipped"].GetListValue().GetValues()
		require.Len(t, skipped, 1)
		require.Equal(t, "first_name", skipped[0].GetStringValue())
	})

	t.Run("empty custom_attributes value clears the attribute", func(t *testing.T) {
		_, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"custom_attributes": map[string]interface{}{"title": "Temp"},
		}))
		require.NoError(t, err)
		rv, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"custom_attributes": map[string]interface{}{"title": ""},
		}))
		require.NoError(t, err)
		require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue())
		e, err := l.client.LdapGetRaw(ctx, userDN, "(objectClass=*)", []string{"title"})
		require.NoError(t, err)
		require.Empty(t, e.GetAttributeValues("title"))
	})

	t.Run("updated_user reflects post-modify state via read-back", func(t *testing.T) {
		rv, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"first_name": "ReadBack",
		}))
		require.NoError(t, err)
		updatedUser := rv.GetFields()["updated_user"]
		require.NotNil(t, updatedUser)
		// updated_user is a JSON-serialized v2.Resource (see actions.NewResourceReturnField,
		// which uses protojson.Marshal with default options, i.e. camelCase field names).
		require.NotEmpty(t, updatedUser.GetStructValue().GetFields()["displayName"].GetStringValue())
	})

	t.Run("named field wins over a colliding custom_attributes entry, which is reported skipped", func(t *testing.T) {
		rv, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"first_name": "NamedWins",
			"custom_attributes": map[string]interface{}{
				"first_name": "CustomLoses",
			},
		}))
		require.NoError(t, err)
		require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue())
		skipped := rv.GetFields()["skipped"].GetListValue().GetValues()
		require.Len(t, skipped, 1)
		require.Equal(t, "first_name", skipped[0].GetStringValue())
		e, err := l.client.LdapGetRaw(ctx, userDN, "(objectClass=*)", []string{attrFirstName})
		require.NoError(t, err)
		require.Equal(t, "NamedWins", e.GetAttributeValue(attrFirstName))
	})

	t.Run("missing user_id is InvalidArgument", func(t *testing.T) {
		args := mkProfileArgs(t, map[string]interface{}{"first_name": "Jane"})
		_, _, err := ub.updateProfile(ctx, args)
		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("malformed (empty resource) user_id is InvalidArgument", func(t *testing.T) {
		_, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, "", "user", map[string]interface{}{
			"first_name": "Jane",
		}))
		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("wrong resource_type_id on user_id is InvalidArgument", func(t *testing.T) {
		_, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "group", map[string]interface{}{
			"first_name": "Jane",
		}))
		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("out-of-scope user DN is NotFound", func(t *testing.T) {
		_, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, "cn=user01,ou=other,dc=example,dc=org", "user", map[string]interface{}{
			"first_name": "Jane",
		}))
		require.Error(t, err)
		require.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("nonexistent DN with every field empty is still NotFound, not a false success", func(t *testing.T) {
		// Proves updateProfile has no empty-mask early return: an all-empty
		// request must still surface a vanished user as NotFound rather than a
		// no-op success.
		_, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, "cn=ghost,ou=users,dc=example,dc=org", "user", map[string]interface{}{
			"first_name": "",
		}))
		require.Error(t, err)
		require.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("password attribute via custom_attributes is rejected", func(t *testing.T) {
		_, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"custom_attributes": map[string]interface{}{"userPassword": "secret"},
		}))
		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("objectClass via custom_attributes is rejected", func(t *testing.T) {
		_, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"custom_attributes": map[string]interface{}{"objectClass": "person"},
		}))
		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("RDN attribute via custom_attributes is skipped, not written", func(t *testing.T) {
		rv, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"custom_attributes": map[string]interface{}{"cn": "renamed"},
		}))
		require.NoError(t, err)
		require.Equal(t, float64(0), rv.GetFields()["applied"].GetNumberValue())
	})

	t.Run("custom_attributes user_id is a raw attribute name, never an alias for uid", func(t *testing.T) {
		// End-to-end proof of the aliasing fix: "user_id" used to resolve through
		// the named-field alias table and rewrite the entry's uid. There is no
		// attribute literally named user_id in the directory's schema, so the
		// correct outcome is a loud server rejection with uid untouched.
		before, err := l.client.LdapGetRaw(ctx, userDN, "(objectClass=*)", []string{attrUserUID})
		require.NoError(t, err)
		uidBefore := before.GetAttributeValues(attrUserUID)

		_, _, err = ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"custom_attributes": map[string]interface{}{"user_id": "hijacked"},
		}))
		require.Error(t, err)

		after, err := l.client.LdapGetRaw(ctx, userDN, "(objectClass=*)", []string{attrUserUID})
		require.NoError(t, err)
		require.Equal(t, uidBefore, after.GetAttributeValues(attrUserUID), "uid must not be touched by a custom_attributes user_id entry")
	})

	t.Run("custom_attributes login is attempted as a raw attribute, not silently skipped", func(t *testing.T) {
		// "login" is one of baton's synthetic profile keys. Through
		// custom_attributes it means the literal attribute of that name, so an
		// undefined attribute must fail loudly rather than be dropped by us with
		// success:true.
		_, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"custom_attributes": map[string]interface{}{"login": "user01"},
		}))
		require.Error(t, err)
	})

	t.Run("clear-vs-error contrast: named empty is a no-op, custom_attributes clearing a MUST attribute is a real server error", func(t *testing.T) {
		// Named-field empty (sn via last_name) is a no-op: it never reaches the
		// server as a clear.
		rv, _, err := ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"last_name": "",
		}))
		require.NoError(t, err)
		require.Equal(t, float64(0), rv.GetFields()["applied"].GetNumberValue())

		// custom_attributes clearing sn (a MUST attribute for person/inetOrgPerson)
		// does reach the server, and the server's schema rejection must surface as
		// an error, not a false success.
		_, _, err = ub.updateProfile(ctx, mkUpdateProfileArgs(t, userDN, "user", map[string]interface{}{
			"custom_attributes": map[string]interface{}{attrLastName: ""},
		}))
		require.Error(t, err)
		e, gerr := l.client.LdapGetRaw(ctx, userDN, "(objectClass=*)", []string{attrLastName})
		require.NoError(t, gerr)
		require.NotEmpty(t, e.GetAttributeValues(attrLastName))
	})
}
