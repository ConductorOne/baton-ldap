package config

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// userStatusConfig builds a connector config from the given YAML on top of the
// minimal set of required fields, and parses it.
func userStatusConfig(t *testing.T, extraYAML string) (*Config, error) {
	t.Helper()

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(
		"url: ldaps://ldap.example.com\n"+
			"bind-dn: cn=admin,dc=example,dc=org\n"+
			"base-dn: dc=example,dc=org\n"+
			extraYAML+"\n")))

	return New(context.Background(), v)
}

// TestNewUserStatusAttributes covers the enable/disable attribute definition:
// what is accepted, what is rejected at startup, and that configured values
// survive viper verbatim.
func TestNewUserStatusAttributes(t *testing.T) {
	tests := []struct {
		name         string
		yaml         string
		wantErr      string
		wantDisabled map[string]string
		wantEnabled  map[string]string
		wantManaged  []string
	}{
		{
			name: "unset by default, nothing managed",
		},
		{
			name:         "disable only is legal",
			yaml:         "disable-user-attributes:\n  revoke: Y\n",
			wantDisabled: map[string]string{"revoke": "Y"},
			wantManaged:  []string{"revoke"},
		},
		{
			name:        "enable only is legal",
			yaml:        "enable-user-attributes:\n  revoke: N\n",
			wantEnabled: map[string]string{"revoke": "N"},
			wantManaged: []string{"revoke"},
		},
		{
			name: "both directions naming the same attributes is legal",
			yaml: "disable-user-attributes:\n  revoke: Y\n" +
				"enable-user-attributes:\n  revoke: N\n",
			wantDisabled: map[string]string{"revoke": "Y"},
			wantEnabled:  map[string]string{"revoke": "N"},
			wantManaged:  []string{"revoke"},
		},
		{
			name: "configured values keep their case",
			yaml: "disable-user-attributes:\n  revoke: \"Yes\"\n" +
				"enable-user-attributes:\n  revoke: \"No\"\n",
			wantDisabled: map[string]string{"revoke": "Yes"},
			wantEnabled:  map[string]string{"revoke": "No"},
			wantManaged:  []string{"revoke"},
		},
		{
			name: "clear on enable is expressible as an empty value",
			yaml: "disable-user-attributes:\n  revoke: Y\n" +
				"enable-user-attributes:\n  revoke: \"\"\n",
			wantDisabled: map[string]string{"revoke": "Y"},
			wantEnabled:  map[string]string{"revoke": ""},
			wantManaged:  []string{"revoke"},
		},
		{
			// viper lowercases nested map keys when it reads a config file
			// (values are untouched); LDAP attribute names are case-insensitive,
			// so the attribute written is the same one.
			name:         "attribute names are whitespace-trimmed and managed attributes are sorted",
			yaml:         "disable-user-attributes:\n  \" revoke \": Y\n  employeeType: Terminated\n",
			wantDisabled: map[string]string{"revoke": "Y", "employeetype": "Terminated"},
			wantManaged:  []string{"employeetype", "revoke"},
		},
		{
			name: "asymmetric attribute sets are rejected",
			yaml: "disable-user-attributes:\n  revoke: Y\n  employeeType: Terminated\n" +
				"enable-user-attributes:\n  revoke: N\n",
			wantErr: "must name the same attributes",
		},
		{
			name:    "asymmetric attribute sets are rejected in the other direction too",
			yaml:    "disable-user-attributes:\n  revoke: Y\n" + "enable-user-attributes:\n  revoke: N\n  employeeType: Active\n",
			wantErr: "must name the same attributes",
		},
		{
			name: "every asymmetric attribute is named, in sorted order",
			yaml: "disable-user-attributes:\n  alpha: \"1\"\n  beta: \"2\"\n" +
				"enable-user-attributes:\n  gamma: \"3\"\n",
			wantErr: `"alpha", "beta", "gamma"`,
		},
		{
			name:    "empty attribute name is rejected",
			yaml:    "disable-user-attributes:\n  \"\": Y\n",
			wantErr: "must not be empty",
		},
		{
			name:    "password attributes are rejected",
			yaml:    "disable-user-attributes:\n  userPassword: Y\n",
			wantErr: "password",
		},
		{
			name:    "objectClass is rejected",
			yaml:    "disable-user-attributes:\n  objectClass: person\n",
			wantErr: "objectClass",
		},
		{
			name: "the same value for both directions is rejected",
			yaml: "disable-user-attributes:\n  revoke: Y\n" +
				"enable-user-attributes:\n  revoke: Y\n",
			wantErr: "same value for both directions",
		},
		{
			name: "the same value differing only in case is rejected",
			yaml: "disable-user-attributes:\n  revoke: Y\n" +
				"enable-user-attributes:\n  revoke: y\n",
			wantErr: "same value for both directions",
		},
		{
			// An empty value on the disable side can never mark an account
			// disabled: the read path needs a present value that MATCHES, so
			// absence reads as enabled. "Disable by clearing" would clear the
			// marker, report success, and leave sync reporting enabled forever.
			name:    "an empty value on the disable side is rejected",
			yaml:    "disable-user-attributes:\n  revoke: \"\"\n",
			wantErr: "empty value",
		},
		{
			name: "an attribute empty in both directions is rejected",
			yaml: "disable-user-attributes:\n  revoke: \"\"\n" +
				"enable-user-attributes:\n  revoke: \"\"\n",
			wantErr: "empty value",
		},
		{
			name: "an empty map is unconfigured, not an error",
			yaml: "disable-user-attributes: {}\n",
		},
		{
			name: "an empty inline string is unconfigured, not an error",
			yaml: "disable-user-attributes: \"\"\n",
		},
		{
			// Defensive path only: this table drives viper directly, so the raw
			// value keeps its YAML type. On the real boot path the SDK's
			// configuration loader has already stringified a scalar, which is why
			// the README documents the quoting rule instead of claiming this is
			// caught.
			name:    "a scalar non-string value is rejected when viper is driven directly",
			yaml:    "disable-user-attributes:\n  revoke: TRUE\n",
			wantErr: "quote it",
		},
		{
			// Reachable on the real boot path, unlike the scalar case above: the
			// SDK's flag pass skips its cast coercion for nested values, so the
			// list arrives intact and is rejected here.
			name:    "a nested list value is rejected",
			yaml:    "disable-user-attributes:\n  revoke:\n    - Y\n",
			wantErr: "values must be strings",
		},
		{
			name:    "a nested map value is rejected",
			yaml:    "disable-user-attributes:\n  revoke:\n    a: b\n",
			wantErr: "values must be strings",
		},
		{
			// Sorted and complete: map order must not decide which attribute the
			// operator is told about, and two boots should not be needed to learn
			// about two mistakes.
			name:    "every empty disable attribute is named, in sorted order",
			yaml:    "disable-user-attributes:\n  zeta: \"\"\n  revoke: \"\"\n  alpha: \"\"\n",
			wantErr: `"alpha", "revoke", "zeta"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := userStatusConfig(t, tc.yaml)
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.wantErr))
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantDisabled, cfg.UserStatusAttributes.Disabled)
			require.Equal(t, tc.wantEnabled, cfg.UserStatusAttributes.Enabled)
			require.Equal(t, tc.wantManaged, cfg.UserStatusAttributes.ManagedAttributes())
		})
	}
}

// TestNewUserStatusAttributesFromEnv covers the environment-variable path, which
// behaves differently from the other two. A nested YAML map and repeated CLI
// flags both reach viper as a map, but an env var arrives as a plain string and
// only parses as a map when it is JSON: cast.ToStringMapString discards its
// parse error, so BATON_DISABLE_USER_ATTRIBUTES='revoke=Y' -- the natural guess,
// and documented next to the CLI example in the README -- used to yield an empty
// map with no error. Everything downstream then passed trivially (nothing
// configured, so nothing invalid) and the action was simply never registered:
// a connector that starts cleanly and silently does nothing.
func TestNewUserStatusAttributesFromEnv(t *testing.T) {
	newEnvViper := func(t *testing.T) *viper.Viper {
		t.Helper()
		v := viper.New()
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(strings.NewReader(
			"url: ldaps://ldap.example.com\n"+
				"bind-dn: cn=admin,dc=example,dc=org\n"+
				"base-dn: dc=example,dc=org\n")))
		// The binding the SDK installs (baton prefix, - to _ replacer).
		v.SetEnvPrefix("baton")
		v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
		v.AutomaticEnv()
		return v
	}

	t.Run("a JSON env var is accepted", func(t *testing.T) {
		t.Setenv("BATON_DISABLE_USER_ATTRIBUTES", `{"revoke":"Y"}`)
		t.Setenv("BATON_ENABLE_USER_ATTRIBUTES", `{"revoke":"N"}`)

		cfg, err := New(context.Background(), newEnvViper(t))
		require.NoError(t, err)
		require.Equal(t, map[string]string{"revoke": "Y"}, cfg.UserStatusAttributes.Disabled)
		require.Equal(t, map[string]string{"revoke": "N"}, cfg.UserStatusAttributes.Enabled)
	})

	t.Run("a flat key=value env var is rejected instead of silently empty", func(t *testing.T) {
		t.Setenv("BATON_DISABLE_USER_ATTRIBUTES", "revoke=Y")

		_, err := New(context.Background(), newEnvViper(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a valid attribute map")
		// The message names the variable the operator must actually set: the
		// SDK's "baton" prefix plus the - to _ replacer. Asserted so it cannot
		// drift from SetEnvPrefix.
		require.Contains(t, err.Error(), "BATON_DISABLE_USER_ATTRIBUTES")
	})

	// An empty JSON object is valid JSON that configures nothing. It must not
	// fail the boot: config.New runs before the connector is built, so a false
	// positive here takes user, group and role sync down with the lifecycle
	// actions.
	t.Run("an empty JSON object is unconfigured, not an error", func(t *testing.T) {
		t.Setenv("BATON_DISABLE_USER_ATTRIBUTES", "{}")

		cfg, err := New(context.Background(), newEnvViper(t))
		require.NoError(t, err)
		require.Nil(t, cfg.UserStatusAttributes.Disabled)
		require.Empty(t, cfg.UserStatusAttributes.ManagedAttributes())
	})
}

// TestNewUserStatusAttributesMapShapes covers the non-string shapes directly,
// since they are what a future viper version could plausibly start returning for
// a config-file value and the ones the empty-vs-unreadable decision turns on.
func TestNewUserStatusAttributesMapShapes(t *testing.T) {
	newViper := func(t *testing.T, value interface{}) *viper.Viper {
		t.Helper()
		v := viper.New()
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(strings.NewReader(
			"url: ldaps://ldap.example.com\n"+
				"bind-dn: cn=admin,dc=example,dc=org\n"+
				"base-dn: dc=example,dc=org\n")))
		if value != nil {
			v.Set(disableUserAttributesField.FieldName, value)
		}
		return v
	}

	t.Run("a zero-length typed map is unconfigured", func(t *testing.T) {
		cfg, err := New(context.Background(), newViper(t, map[string]string{}))
		require.NoError(t, err)
		require.Nil(t, cfg.UserStatusAttributes.Disabled)
	})

	t.Run("a zero-length interface map is unconfigured", func(t *testing.T) {
		cfg, err := New(context.Background(), newViper(t, map[string]interface{}{}))
		require.NoError(t, err)
		require.Nil(t, cfg.UserStatusAttributes.Disabled)
	})

	t.Run("a flag-style string map is configured", func(t *testing.T) {
		cfg, err := New(context.Background(), newViper(t, map[string]string{"revoke": "Y"}))
		require.NoError(t, err)
		require.Equal(t, map[string]string{"revoke": "Y"}, cfg.UserStatusAttributes.Disabled)
	})

	t.Run("a non-map value is an error naming the type", func(t *testing.T) {
		_, err := New(context.Background(), newViper(t, 42))
		require.Error(t, err)
		require.Contains(t, err.Error(), "got int")
	})
}

// TestNewUserStatusAttributesDuplicateNames covers two attribute names folding
// to the same LDAP attribute within one map. viper lowercases nested map keys
// when it reads a config file, so this shape only reaches New() through a
// programmatic Set -- but it must still be rejected rather than silently
// producing a mask entry that buildUserAttrChanges has to skip.
func TestNewUserStatusAttributesDuplicateNames(t *testing.T) {
	v := viper.New()
	v.Set("url", "ldaps://ldap.example.com")
	v.Set("bind-dn", "cn=admin,dc=example,dc=org")
	v.Set("base-dn", "dc=example,dc=org")
	v.Set("disable-user-attributes", map[string]string{"revoke": "Y", "REVOKE": "N"})

	_, err := New(context.Background(), v)
	require.Error(t, err)
	require.Contains(t, err.Error(), "more than once")
}

// TestNewUserStatusAttributesValueNotLowercased pins the one thing viper must
// not do to a configured value: the comparison against directory values is
// case-insensitive, but the value written must be exactly what was configured.
func TestNewUserStatusAttributesValueNotLowercased(t *testing.T) {
	cfg, err := userStatusConfig(t, "disable-user-attributes:\n  revoke: \"Y\"\n")
	require.NoError(t, err)

	require.Equal(t, "Y", cfg.UserStatusAttributes.Disabled["revoke"])
	require.NotEqual(t, "y", cfg.UserStatusAttributes.Disabled["revoke"])
}
