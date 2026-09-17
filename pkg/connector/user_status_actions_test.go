package connector

import (
	"context"
	"testing"

	"github.com/conductorone/baton-ldap/pkg/config"
	config_sdk "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// symmetricStatusDefinition is a valid configuration (both directions name the
// same attributes), used by the read-path tests below.
func symmetricStatusDefinition() config.UserStatusAttributes {
	return config.UserStatusAttributes{
		Disabled: map[string]string{"revoke": "Y", "employeeType": "Terminated"},
		Enabled:  map[string]string{"revoke": "N", "employeeType": "Active"},
	}
}

// mkStatusArgs builds an enable_user/disable_user args struct, including the
// user_id ResourceIdField wire shape actions.GetResourceIDArg expects.
func mkStatusArgs(t *testing.T, userDN, resourceType string) *structpb.Struct {
	t.Helper()
	userID := map[string]interface{}{"resource_id": userDN}
	if resourceType != "" {
		userID["resource_type_id"] = resourceType
	}
	args, err := structpb.NewStruct(map[string]interface{}{argUserID: userID})
	require.NoError(t, err)
	return args
}

func TestBuildUserStatusAttrs(t *testing.T) {
	t.Run("returns exactly the configured direction, with a sorted mask", func(t *testing.T) {
		attrs, mask := buildUserStatusAttrs(map[string]string{
			"revoke":       "Y",
			"employeeType": "Terminated",
		})
		require.Equal(t, map[string]string{"revoke": "Y", "employeeType": "Terminated"}, attrs)
		require.Equal(t, []string{"employeeType", "revoke"}, mask)
	})

	t.Run("direction isolation: an empty direction writes nothing, never the other direction's attributes", func(t *testing.T) {
		def := symmetricStatusDefinition()
		for _, tc := range []struct {
			name      string
			direction map[string]string
			other     map[string]string
		}{
			{"disabled", def.Disabled, def.Enabled},
			{"enabled", def.Enabled, def.Disabled},
		} {
			t.Run(tc.name, func(t *testing.T) {
				attrs, mask := buildUserStatusAttrs(tc.direction)
				require.Equal(t, tc.direction, attrs)
				require.Equal(t, []string{"employeeType", "revoke"}, mask)
				// The other direction's values are the only thing that differs
				// between the two maps, so this is the sharp assertion: the
				// value written is this direction's, never the other's.
				for name, value := range attrs {
					require.NotEqual(t, tc.other[name], value)
				}

				// An empty direction can never yield the other direction's
				// attributes either.
				attrs, mask = buildUserStatusAttrs(nil)
				require.Empty(t, attrs)
				require.Empty(t, mask)
			})
		}
	})

	t.Run("an empty configured value is kept, so it clears the attribute", func(t *testing.T) {
		attrs, mask := buildUserStatusAttrs(map[string]string{"revoke": ""})
		require.Equal(t, map[string]string{"revoke": ""}, attrs)
		require.Equal(t, []string{"revoke"}, mask)
	})

	t.Run("mask order is stable across repeated calls (map iteration is randomized)", func(t *testing.T) {
		configured := map[string]string{"m": "1", "z": "2", "a": "3", "q": "4", "b": "5", "y": "6"}
		var first []string
		for i := 0; i < 25; i++ {
			_, mask := buildUserStatusAttrs(configured)
			if first == nil {
				first = mask
			} else {
				require.Equal(t, first, mask, "mask order must be stable despite map iteration randomization")
			}
		}
		require.Equal(t, []string{"a", "b", "m", "q", "y", "z"}, first)
	})

	t.Run("the returned attrs are a copy, never the connector's configuration map", func(t *testing.T) {
		configured := map[string]string{"revoke": "Y"}
		attrs, _ := buildUserStatusAttrs(configured)
		attrs["revoke"] = "mutated"
		require.Equal(t, "Y", configured["revoke"])
	})
}

func TestParseUserStatusConfiguredAttributes(t *testing.T) {
	tests := []struct {
		name          string
		definition    config.UserStatusAttributes
		attributes    map[string][]string
		want          v2.Status_ResourceStatus
		wantUnmatched []string
	}{
		{
			name:       "configured disabled value wins over nsAccountLock=false",
			definition: symmetricStatusDefinition(),
			attributes: map[string][]string{"revoke": {"Y"}, "nsAccountLock": {"FALSE"}},
			want:       v2.Status_RESOURCE_STATUS_DISABLED,
		},
		{
			name:       "configured enabled value wins over the userAccountControl disabled bit",
			definition: symmetricStatusDefinition(),
			attributes: map[string][]string{"revoke": {"N"}, "userAccountControl": {"514"}},
			want:       v2.Status_RESOURCE_STATUS_ENABLED,
		},
		{
			name:       "any disabled attribute wins, whichever of the two carries it",
			definition: symmetricStatusDefinition(),
			attributes: map[string][]string{"revoke": {"N"}, "employeeType": {"Terminated"}},
			want:       v2.Status_RESOURCE_STATUS_DISABLED,
		},
		{
			name:       "any disabled attribute wins in the other order too",
			definition: symmetricStatusDefinition(),
			attributes: map[string][]string{"revoke": {"Y"}, "employeeType": {"Active"}},
			want:       v2.Status_RESOURCE_STATUS_DISABLED,
		},
		{
			name:       "a multi-valued attribute counts when any value matches",
			definition: symmetricStatusDefinition(),
			attributes: map[string][]string{"employeeType": {"Engineering", "Terminated"}},
			want:       v2.Status_RESOURCE_STATUS_DISABLED,
		},
		{
			name:       "comparison is case-insensitive and whitespace-trimmed",
			definition: symmetricStatusDefinition(),
			attributes: map[string][]string{"revoke": {" y "}},
			want:       v2.Status_RESOURCE_STATUS_DISABLED,
		},
		{
			name:          "a present-but-unmatched value contributes no verdict and falls through",
			definition:    symmetricStatusDefinition(),
			attributes:    map[string][]string{"revoke": {"maybe"}, "nsAccountLock": {"FALSE"}},
			want:          v2.Status_RESOURCE_STATUS_ENABLED,
			wantUnmatched: []string{"revoke"},
		},
		{
			name:          "an unmatched attribute is still reported when another attribute decides the status",
			definition:    symmetricStatusDefinition(),
			attributes:    map[string][]string{"revoke": {"Y"}, "employeeType": {"Engineering"}},
			want:          v2.Status_RESOURCE_STATUS_DISABLED,
			wantUnmatched: []string{"employeeType"},
		},
		{
			name:          "a present-but-unmatched value with no fallback rule stays unspecified",
			definition:    symmetricStatusDefinition(),
			attributes:    map[string][]string{"revoke": {"maybe"}},
			want:          v2.Status_RESOURCE_STATUS_UNSPECIFIED,
			wantUnmatched: []string{"revoke"},
		},
		{
			name:       "a cleared attribute (clear-on-enable) contributes no verdict",
			definition: config.UserStatusAttributes{Disabled: map[string]string{"revoke": "Y"}, Enabled: map[string]string{"revoke": ""}},
			attributes: map[string][]string{"cn": {"user01"}},
			want:       v2.Status_RESOURCE_STATUS_UNSPECIFIED,
		},
		{
			name:       "with no definition configured the built-in rules still decide",
			attributes: map[string][]string{"nsAccountLock": {"TRUE"}},
			want:       v2.Status_RESOURCE_STATUS_DISABLED,
		},
		{
			name:       "the built-in rules decide when the definition yields nothing",
			definition: symmetricStatusDefinition(),
			attributes: map[string][]string{"userAccountControl": {"514"}},
			want:       v2.Status_RESOURCE_STATUS_DISABLED,
		},
		{
			name:       "the built-in rules report enabled for a cleared ACCOUNTDISABLE bit",
			definition: symmetricStatusDefinition(),
			attributes: map[string][]string{"userAccountControl": {"512"}},
			want:       v2.Status_RESOURCE_STATUS_ENABLED,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := entryWith("cn=user01,ou=users,dc=example,dc=org", tc.attributes)
			status, unmatched, err := parseUserStatus(entry, tc.definition)
			require.NoError(t, err)
			require.Equal(t, tc.want, status)
			require.Equal(t, tc.wantUnmatched, unmatched)
		})
	}

	t.Run("a malformed userAccountControl is still an error", func(t *testing.T) {
		entry := entryWith("cn=user01,ou=users,dc=example,dc=org", map[string][]string{"userAccountControl": {"not-a-number"}})
		_, _, err := parseUserStatus(entry, symmetricStatusDefinition())
		require.Error(t, err)
	})
}

func TestAssertStatusAttrsWritten(t *testing.T) {
	dn := "cn=user01,ou=users,dc=example,dc=org"

	tests := []struct {
		name    string
		attrs   map[string]string
		mask    []string
		entry   map[string][]string
		wantErr bool
	}{
		{
			name:  "configured value present",
			attrs: map[string]string{"revoke": "Y"},
			mask:  []string{"revoke"},
			entry: map[string][]string{"revoke": {"Y"}},
		},
		{
			name:  "case and whitespace differences still match",
			attrs: map[string]string{"revoke": "Y"},
			mask:  []string{"revoke"},
			entry: map[string][]string{"REVOKE": {" y "}},
		},
		{
			name:  "any value of a multi-valued attribute matching is enough",
			attrs: map[string]string{"employeeType": "Terminated"},
			mask:  []string{"employeeType"},
			entry: map[string][]string{"employeeType": {"Engineering", "Terminated"}},
		},
		{
			name:  "an attribute configured to clear and absent is correct",
			attrs: map[string]string{"revoke": ""},
			mask:  []string{"revoke"},
			entry: map[string][]string{"cn": {"user01"}},
		},
		{
			name:    "an attribute configured to clear but still present is a mismatch",
			attrs:   map[string]string{"revoke": ""},
			mask:    []string{"revoke"},
			entry:   map[string][]string{"revoke": {"Y"}},
			wantErr: true,
		},
		{
			name:    "an absent attribute is a mismatch",
			attrs:   map[string]string{"revoke": "Y"},
			mask:    []string{"revoke"},
			entry:   map[string][]string{"cn": {"user01"}},
			wantErr: true,
		},
		{
			name:    "a different value is a mismatch",
			attrs:   map[string]string{"revoke": "Y"},
			mask:    []string{"revoke"},
			entry:   map[string][]string{"revoke": {"N"}},
			wantErr: true,
		},
		{
			name:    "a mask entry with no configured value is a mismatch",
			attrs:   map[string]string{},
			mask:    []string{"revoke"},
			entry:   map[string][]string{"revoke": {"Y"}},
			wantErr: true,
		},
		{
			name:  "the whole batch passes when every attribute landed",
			attrs: map[string]string{"revoke": "Y", "employeeType": "Terminated"},
			mask:  []string{"employeeType", "revoke"},
			entry: map[string][]string{"revoke": {"Y"}, "employeeType": {"Terminated"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := assertStatusAttrsWritten(entryWith(dn, tc.entry), tc.attrs, tc.mask)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestUserStatusActionSchemas(t *testing.T) {
	tests := []struct {
		name       string
		schema     func() *v2.BatonActionSchema
		wantName   string
		wantAction v2.ActionType
	}{
		{"enable_user", enableUserActionSchema, actionNameEnableUser, v2.ActionType_ACTION_TYPE_ACCOUNT_ENABLE},
		{"disable_user", disableUserActionSchema, actionNameDisableUser, v2.ActionType_ACTION_TYPE_ACCOUNT_DISABLE},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			schema := tc.schema()
			require.Equal(t, tc.wantName, schema.GetName())
			// The base ACTION_TYPE_ACCOUNT is combined with the specific lifecycle
			// type, matching baton-okta's enable_user/disable_user and
			// baton-active-directory's.
			require.Equal(t, []v2.ActionType{v2.ActionType_ACTION_TYPE_ACCOUNT, tc.wantAction}, schema.GetActionType())

			var userIDArg *config_sdk.Field
			for _, arg := range schema.GetArguments() {
				if arg.GetName() == argUserID {
					userIDArg = arg
				}
			}
			require.NotNil(t, userIDArg, "user_id argument must be present")
			require.True(t, userIDArg.GetIsRequired())
			require.NotNil(t, userIDArg.GetResourceIdField())
			require.Contains(t, userIDArg.GetResourceIdField().GetRules().GetAllowedResourceTypeIds(), resourceTypeUser.Id)

			returnTypes := map[string]*config_sdk.Field{}
			for _, rt := range schema.GetReturnTypes() {
				returnTypes[rt.GetName()] = rt
			}
			require.NotNil(t, returnTypes["success"].GetBoolField())
			require.NotNil(t, returnTypes["status"].GetStringField())
			require.NotNil(t, returnTypes["applied"].GetIntField())
			require.NotNil(t, returnTypes["skipped"].GetStringSliceField())
			require.NotNil(t, returnTypes["updated_user"].GetResourceField())

			// Regression guard: the schema must be freshly built per call --
			// registration mutates it in place (ResourceTypeId), so a shared
			// package-level value would leak that mutation.
			schema2 := tc.schema()
			require.NotSame(t, schema, schema2)
			schema.SetResourceTypeId(resourceTypeUser.Id)
			require.Empty(t, schema2.GetResourceTypeId())
		})
	}
}

// TestGlobalActionsUserStatusRegistration pins the conditional registration:
// ConductorOne must never be offered a lifecycle action the configuration
// cannot carry out. The handler identity is irrelevant here, so the connector's
// client is left nil.
func TestGlobalActionsUserStatusRegistration(t *testing.T) {
	tests := []struct {
		name        string
		definition  config.UserStatusAttributes
		wantEnable  bool
		wantDisable bool
	}{
		{
			name:       "nothing configured registers neither",
			definition: config.UserStatusAttributes{},
		},
		{
			name:        "disable only registers disable_user",
			definition:  config.UserStatusAttributes{Disabled: map[string]string{"revoke": "Y"}},
			wantDisable: true,
		},
		{
			name:       "enable only registers enable_user",
			definition: config.UserStatusAttributes{Enabled: map[string]string{"revoke": "N"}},
			wantEnable: true,
		},
		{
			name:        "both directions register both",
			definition:  symmetricStatusDefinition(),
			wantEnable:  true,
			wantDisable: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := &LDAP{config: &config.Config{UserStatusAttributes: tc.definition}}
			reg := newTestRegistry()
			require.NoError(t, l.GlobalActions(context.Background(), reg))

			require.Contains(t, reg.schemas, actionNameCreateOU)
			if tc.wantDisable {
				require.Contains(t, reg.schemas, actionNameDisableUser)
			} else {
				require.NotContains(t, reg.schemas, actionNameDisableUser)
			}
			if tc.wantEnable {
				require.Contains(t, reg.schemas, actionNameEnableUser)
			} else {
				require.NotContains(t, reg.schemas, actionNameEnableUser)
			}
			require.Len(t, reg.schemas, 1+boolToInt(tc.wantDisable)+boolToInt(tc.wantEnable))
		})
	}
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// TestUserStatusActionEmptyDirection pins the guard behind the "no false
// success" rule: a direction with nothing configured must fail rather than
// report success having written no attribute. Registration withholds the action
// entirely in that case, so the handler is reached this way only by a caller the
// registration check did not cover. The connector's client is left nil -- the
// guard runs before any I/O.
func TestUserStatusActionEmptyDirection(t *testing.T) {
	l := &LDAP{config: &config.Config{}}
	userDN := "cn=user01,ou=users,dc=example,dc=org"

	_, _, err := l.disableUser(context.Background(), mkStatusArgs(t, userDN, "user"))
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	_, _, err = l.enableUser(context.Background(), mkStatusArgs(t, userDN, "user"))
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// TestUserStatusActions exercises enable_user/disable_user end to end against a
// real (containerized) OpenLDAP server. It requires Docker and is not runnable
// in a sandbox without it; it is included here so the handlers are covered as
// soon as Docker is available, and so it is compile-checked by `go vet` even
// when it cannot be executed.
func TestUserStatusActions(t *testing.T) {
	ctx := ctxzap.ToContext(context.Background(), zap.Must(zap.NewDevelopment()))

	l, err := createConnector(ctx, t, "")
	require.NoError(t, err)

	const (
		userDN         = "cn=user01,ou=users,dc=example,dc=org"
		outOfScopeDN   = "cn=user01,ou=other,dc=example,dc=org"
		attrStatusFlag = "employeeType"
	)

	setDefinition := func(disabled, enabled map[string]string) {
		l.config.UserStatusAttributes = config.UserStatusAttributes{Disabled: disabled, Enabled: enabled}
	}

	valuesOf := func(t *testing.T, dn, attr string) []string {
		t.Helper()
		// Always request every user attribute: asking for an attribute the
		// directory does not define is not portable across servers.
		entry, err := l.client.LdapGetRaw(ctx, dn, "(objectClass=*)", []string{"*"})
		require.NoError(t, err)
		return entry.GetAttributeValues(attr)
	}

	t.Run("disable, disable again (idempotent), enable, then disable round-trips", func(t *testing.T) {
		setDefinition(map[string]string{attrStatusFlag: "Disabled"}, map[string]string{attrStatusFlag: "Enabled"})

		rv, _, err := l.disableUser(ctx, mkStatusArgs(t, userDN, "user"))
		require.NoError(t, err)
		require.True(t, rv.GetFields()["success"].GetBoolValue())
		require.Equal(t, statusNameDisabled, rv.GetFields()["status"].GetStringValue())
		require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue())
		require.Empty(t, rv.GetFields()["skipped"].GetListValue().GetValues())
		require.Equal(t, []string{"Disabled"}, valuesOf(t, userDN, attrStatusFlag))

		// The second disable call lands on an already-disabled account: a
		// legitimate success that applies nothing.
		rv, _, err = l.disableUser(ctx, mkStatusArgs(t, userDN, "user"))
		require.NoError(t, err)
		require.Equal(t, statusNameDisabled, rv.GetFields()["status"].GetStringValue())
		require.Equal(t, float64(0), rv.GetFields()["applied"].GetNumberValue(), "the account is already disabled")
		require.Empty(t, rv.GetFields()["skipped"].GetListValue().GetValues(), "an already-satisfied attribute is not a skip")

		rv, _, err = l.enableUser(ctx, mkStatusArgs(t, userDN, "user"))
		require.NoError(t, err)
		require.Equal(t, statusNameEnabled, rv.GetFields()["status"].GetStringValue())
		require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue())
		require.Equal(t, []string{"Enabled"}, valuesOf(t, userDN, attrStatusFlag))

		rv, _, err = l.disableUser(ctx, mkStatusArgs(t, userDN, "user"))
		require.NoError(t, err)
		require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue(), "enabling really did change the attribute")
		require.Equal(t, []string{"Disabled"}, valuesOf(t, userDN, attrStatusFlag))
	})

	t.Run("repeating an identical call succeeds and applies nothing", func(t *testing.T) {
		setDefinition(map[string]string{attrStatusFlag: "Disabled"}, map[string]string{attrStatusFlag: "Enabled"})

		_, _, err := l.disableUser(ctx, mkStatusArgs(t, userDN, "user"))
		require.NoError(t, err)

		rv, _, err := l.disableUser(ctx, mkStatusArgs(t, userDN, "user"))
		require.NoError(t, err)
		require.True(t, rv.GetFields()["success"].GetBoolValue())
		require.Equal(t, float64(0), rv.GetFields()["applied"].GetNumberValue())
		require.Empty(t, rv.GetFields()["skipped"].GetListValue().GetValues(), "an already-satisfied attribute is not a skip")
	})

	t.Run("every configured attribute is written", func(t *testing.T) {
		setDefinition(map[string]string{attrStatusFlag: "Terminated", "description": "disabled by baton"}, nil)

		rv, _, err := l.disableUser(ctx, mkStatusArgs(t, userDN, "user"))
		require.NoError(t, err)
		require.Equal(t, float64(2), rv.GetFields()["applied"].GetNumberValue())
		require.Equal(t, []string{"Terminated"}, valuesOf(t, userDN, attrStatusFlag))
		require.Equal(t, []string{"disabled by baton"}, valuesOf(t, userDN, "description"))
	})

	t.Run("enabling replaces the disabled value rather than leaving it behind", func(t *testing.T) {
		setDefinition(map[string]string{attrStatusFlag: "Disabled"}, map[string]string{attrStatusFlag: "Enabled"})
		_, _, err := l.disableUser(ctx, mkStatusArgs(t, userDN, "user"))
		require.NoError(t, err)
		require.Equal(t, []string{"Disabled"}, valuesOf(t, userDN, attrStatusFlag))

		rv, _, err := l.enableUser(ctx, mkStatusArgs(t, userDN, "user"))
		require.NoError(t, err)
		require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue())
		require.Equal(t, []string{"Enabled"}, valuesOf(t, userDN, attrStatusFlag))
	})

	t.Run("clearing on enable removes the marker", func(t *testing.T) {
		setDefinition(map[string]string{attrStatusFlag: "Disabled"}, map[string]string{attrStatusFlag: ""})

		_, _, err := l.disableUser(ctx, mkStatusArgs(t, userDN, "user"))
		require.NoError(t, err)
		require.Equal(t, []string{"Disabled"}, valuesOf(t, userDN, attrStatusFlag))

		rv, _, err := l.enableUser(ctx, mkStatusArgs(t, userDN, "user"))
		require.NoError(t, err)
		require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue())
		require.Empty(t, valuesOf(t, userDN, attrStatusFlag))

		// The cleared state is the enabled state: the read path falls through
		// (the absence of the disabled marker), it does not match a value.
		entry, err := l.client.LdapGetRaw(ctx, userDN, "(objectClass=*)", []string{attrStatusFlag, attrNSAccountLock})
		require.NoError(t, err)
		readStatus, _, err := parseUserStatus(entry, l.config.UserStatusAttributes)
		require.NoError(t, err)
		require.Equal(t, v2.Status_RESOURCE_STATUS_UNSPECIFIED, readStatus)
	})

	t.Run("an RDN attribute in the configuration fails on the first and every repeated call", func(t *testing.T) {
		setDefinition(map[string]string{"cn": "renamed"}, nil)

		for attempt := 1; attempt <= 2; attempt++ {
			_, _, err := l.disableUser(ctx, mkStatusArgs(t, userDN, "user"))
			require.Errorf(t, err, "attempt %d must fail", attempt)
			require.Equal(t, codes.FailedPrecondition, status.Code(err))
			require.Contains(t, err.Error(), "cn")
		}
		require.Equal(t, []string{"user01"}, valuesOf(t, userDN, "cn"))
	})

	t.Run("an attribute the directory does not define fails, never a false success", func(t *testing.T) {
		// Regression for the modify-masking trap: LdapModify would mask the
		// server's rejection to nil and report success.
		setDefinition(map[string]string{"revoke": "Y"}, nil)

		_, _, err := l.disableUser(ctx, mkStatusArgs(t, userDN, "user"))
		require.Error(t, err)
		require.Empty(t, valuesOf(t, userDN, "revoke"))
	})

	t.Run("a write the directory normalizes away fails the read-back verification", func(t *testing.T) {
		// OpenLDAP pretty-prints DN-syntax values on store, so the value the
		// connector writes is not the value it reads back: the modify lands, and
		// the verification step is what catches it. Without that step the action
		// would report success for a state the directory does not hold.
		const configured = "CN=someone, OU=users, DC=example, DC=org"
		setDefinition(map[string]string{"manager": configured}, nil)

		_, _, err := l.disableUser(ctx, mkStatusArgs(t, userDN, "user"))
		require.Error(t, err)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))

		written := valuesOf(t, userDN, "manager")
		require.NotEmpty(t, written, "the write itself must have landed")
		require.NotEqual(t, configured, written[0], "the directory normalized the value away from the configured one")
	})

	t.Run("an out-of-scope DN is NotFound", func(t *testing.T) {
		setDefinition(map[string]string{attrStatusFlag: "Disabled"}, nil)

		_, _, err := l.disableUser(ctx, mkStatusArgs(t, outOfScopeDN, "user"))
		require.Error(t, err)
		require.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("a missing or malformed user_id is InvalidArgument", func(t *testing.T) {
		setDefinition(map[string]string{attrStatusFlag: "Disabled"}, nil)

		args, aerr := structpb.NewStruct(map[string]interface{}{})
		require.NoError(t, aerr)
		_, _, err := l.disableUser(ctx, args)
		require.Equal(t, codes.InvalidArgument, status.Code(err))

		_, _, err = l.disableUser(ctx, mkStatusArgs(t, "", "user"))
		require.Equal(t, codes.InvalidArgument, status.Code(err))

		_, _, err = l.disableUser(ctx, mkStatusArgs(t, userDN, "group"))
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}

// revokeSchemaLDIF defines the `revoke` attribute the way a directory like
// IDMWorks' would. It is loaded into the running server's cn=config, because
// `revoke` is in no standard schema and a plain LDIF fixture using it fails
// with result code 17 (undefinedAttributeType).
const revokeSchemaLDIF = `dn: cn=revoke,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: revoke
olcAttributeTypes: ( 1.3.6.1.4.1.99999.1.1 NAME 'revoke' DESC 'account enabled/disabled marker (test)' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
`

// TestUserStatusActionsRevokeAttribute is the end-to-end test of the literal
// IDMWorks shape (revoke=Y disabled, revoke=N enabled) against a directory that
// actually defines `revoke`. It requires Docker.
func TestUserStatusActionsRevokeAttribute(t *testing.T) {
	ctx := ctxzap.ToContext(context.Background(), zap.Must(zap.NewDevelopment()))

	l, container, err := createConnectorWithContainer(ctx, t, "")
	require.NoError(t, err)

	// Same root-exec pattern the dyngroup schema load uses: the bitnami
	// container user has manage access to cn=config over the local ldapi socket.
	require.NoError(t, container.CopyToContainer(ctx, []byte(revokeSchemaLDIF), "/tmp/revoke-schema.ldif", 0o600))
	exitCode, _, err := container.Exec(ctx, []string{
		"ldapadd", "-Y", "EXTERNAL",
		"-H", "ldapi://%2Fopt%2Fbitnami%2Fopenldap%2Fvar%2Frun%2Fldapi",
		"-f", "/tmp/revoke-schema.ldif",
	})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode, "loading the revoke schema must succeed")

	// `revoke` is not permitted by inetOrgPerson, so the entry opts into
	// extensibleObject to be allowed to carry it.
	const userDN = "cn=revokeuser,ou=users,dc=example,dc=org"
	addReq := ldap3.NewAddRequest(userDN, nil)
	addReq.Attribute("objectClass", []string{"inetOrgPerson", "extensibleObject", ldapObjectClassTop})
	addReq.Attribute("cn", []string{"revokeuser"})
	addReq.Attribute("sn", []string{"Revoke"})
	addReq.Attribute("uid", []string{"revokeuser"})
	require.NoError(t, l.client.LdapAdd(ctx, addReq))

	l.config.UserStatusAttributes = config.UserStatusAttributes{
		Disabled: map[string]string{"revoke": "Y"},
		Enabled:  map[string]string{"revoke": "N"},
	}

	readStatus := func(t *testing.T) v2.Status_ResourceStatus {
		t.Helper()
		entry, rerr := l.client.LdapGetRaw(ctx, userDN, "(objectClass=*)", []string{"*"})
		require.NoError(t, rerr)
		resolved, _, rerr := parseUserStatus(entry, l.config.UserStatusAttributes)
		require.NoError(t, rerr)
		return resolved
	}

	rv, _, err := l.disableUser(ctx, mkStatusArgs(t, userDN, "user"))
	require.NoError(t, err)
	require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue())
	require.Equal(t, v2.Status_RESOURCE_STATUS_DISABLED, readStatus(t))

	rv, _, err = l.enableUser(ctx, mkStatusArgs(t, userDN, "user"))
	require.NoError(t, err)
	require.Equal(t, float64(1), rv.GetFields()["applied"].GetNumberValue())
	require.Equal(t, v2.Status_RESOURCE_STATUS_ENABLED, readStatus(t))

	rv, _, err = l.disableUser(ctx, mkStatusArgs(t, userDN, "user"))
	require.NoError(t, err)
	require.Equal(t, float64(0), rv.GetFields()["applied"].GetNumberValue())
	require.Equal(t, v2.Status_RESOURCE_STATUS_DISABLED, readStatus(t))
}
