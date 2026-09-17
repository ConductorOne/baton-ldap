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
			name: "an attribute empty in both directions is rejected",
			yaml: "disable-user-attributes:\n  revoke: \"\"\n" +
				"enable-user-attributes:\n  revoke: \"\"\n",
			wantErr: "same value for both directions",
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
