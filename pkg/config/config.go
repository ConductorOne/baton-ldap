package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/conductorone/baton-ldap/pkg/ldap"
	"github.com/conductorone/baton-sdk/pkg/field"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	urlField = field.StringField("url", field.WithDescription(`The URL to connect to. Example: "ldaps://baton.example.com"`))

	baseDNField   = field.StringField("base-dn", field.WithDescription(`The base DN to search from. Example: "DC=baton,DC=example,DC=com"`))
	passwordField = field.StringField("password", field.WithDescription("The password to bind to the LDAP server"), field.WithIsSecret(true))
	bindDNField   = field.StringField("bind-dn", field.WithDescription("The user DN to bind to the LDAP server"))

	userSearchDNField = field.StringField("user-search-dn",
		field.WithDescription("The DN to search for users under. Example: 'OU=Users,DC=baton,DC=example,DC=com'"))
	groupSearchDNField = field.StringField("group-search-dn",
		field.WithDescription("The DN to search for groups under. Example: 'OU=Groups,DC=baton,DC=example,DC=com'"))
	roleSearchDNField = field.StringField("role-search-dn",
		field.WithDescription("The DN to search for roles under. Example: 'OU=Roles,DC=baton,DC=example,DC=com'"))
	filterField = field.StringField("filter",
		field.WithDescription("An optional filter to add to all LDAP searches. Example: '(!(objectClass=computer))' will exclude all entries with a computer object class"))

	//revive:disable-next-line:line-length-limit
	disableOperationalAttrsField = field.BoolField("disable-operational-attrs", field.WithDescription("Disable fetching operational attributes. Some LDAP servers don't support these. If disabled, created_at and last login info will not be fetched"))
	insecureSkipVerifyField      = field.BoolField("insecure-skip-verify", field.WithDescription("If connecting over TLS, skip verifying the server certificate"))

	// The enable/disable definition is deliberately not defaulted, and
	// deliberately not suggested either: revoke=Y/N is one customer's marker, and
	// a value pre-filled into the configuration UI is accepted as-is by every
	// other tenant, registering lifecycle actions against an attribute their
	// directory does not define. The example lives in the description and the
	// README instead, where it informs without configuring anything.
	disableUserAttributesField = field.StringMapField("disable-user-attributes",
		field.WithDescription("Map of LDAP attribute name to the value that marks a user account as disabled, for example \"revoke: Y\". Unset by default."))
	enableUserAttributesField = field.StringMapField("enable-user-attributes",
		field.WithDescription("Map of LDAP attribute name to the value that marks a user account as enabled, for example \"revoke: N\". "+
			"Unset by default. When both directions are configured they must name the same attributes."))
)

var (
	// depreciated: use urlField
	domainField = field.StringField("domain", field.WithDescription(`The fully-qualified LDAP domain to connect to. Example: "baton.example.com" (deprecated, use url`), field.WithHidden(true))

	// depreciated: use userBindDNField
	userDNField = field.StringField("user-dn", field.WithDescription("The user DN to bind to the LDAP server (deprecated, use user-bind-dn)"), field.WithHidden(true))
)

// configurationFields defines the external configuration required for the connector to run.
var ConfigurationFields = []field.SchemaField{
	urlField,
	domainField,
	baseDNField,
	passwordField,
	userDNField,
	bindDNField,
	userSearchDNField,
	groupSearchDNField,
	roleSearchDNField,
	insecureSkipVerifyField,
	disableOperationalAttrsField,
	disableUserAttributesField,
	enableUserAttributesField,
	filterField,
}

var ConfigRelations = []field.SchemaFieldRelationship{
	field.FieldsMutuallyExclusive(domainField, urlField),
	field.FieldsAtLeastOneUsed(domainField, urlField),
}

var Configuration = field.NewConfiguration(ConfigurationFields,
	field.WithConnectorDisplayName("LDAP"),
	field.WithConstraints(ConfigRelations...),
)

func New(ctx context.Context, v *viper.Viper) (*Config, error) {
	l := ctxzap.Extract(ctx)

	rv := &Config{}
	if urlstr := v.GetString(urlField.FieldName); urlstr != "" {
		ux, err := url.Parse(urlstr)
		if err != nil {
			return nil, fmt.Errorf("error parsing url: %w", err)
		}
		switch ux.Scheme {
		case "ldap", "ldaps":
			rv.ServerURL = ux
		default:
			return nil, fmt.Errorf("unsupported scheme: %s", ux.Scheme)
		}
	} else if domainValue := v.GetString(domainField.FieldName); domainValue != "" {
		rv.ServerURL = &url.URL{
			Scheme: "ldap",
			Host:   domainValue,
		}
	}

	if rv.ServerURL == nil {
		return nil, fmt.Errorf("missing server URL")
	}

	if baseDNValue := v.GetString(baseDNField.FieldName); baseDNValue != "" {
		baseDN, err := ldap.CanonicalizeDN(baseDNValue)
		if err != nil {
			return nil, fmt.Errorf("error parsing base-dn: %w", err)
		}
		rv.BaseDN = baseDN
	}

	if userDNValue := v.GetString(userDNField.FieldName); userDNValue != "" {
		userDN, err := ldap.CanonicalizeDN(userDNValue)
		if err != nil {
			return nil, fmt.Errorf("error parsing user-dn: %w", err)
		}
		rv.BindDN = userDN
	}

	if bindDNValue := v.GetString(bindDNField.FieldName); bindDNValue != "" {
		bindDN, err := ldap.CanonicalizeDN(bindDNValue)
		if err != nil {
			return nil, fmt.Errorf("error parsing bind-dn: %w", err)
		}
		rv.BindDN = bindDN
	}

	if rv.BindDN == nil {
		return nil, fmt.Errorf("missing bind-dn")
	}

	if userSearchDNValue := v.GetString(userSearchDNField.FieldName); userSearchDNValue != "" {
		userSearchDN, err := ldap.CanonicalizeDN(userSearchDNValue)
		if err != nil {
			return nil, fmt.Errorf("error parsing user-search-dn: %w", err)
		}
		rv.UserSearchDN = userSearchDN
	} else {
		rv.UserSearchDN = rv.BaseDN
	}

	if groupSearchDNValue := v.GetString(groupSearchDNField.FieldName); groupSearchDNValue != "" {
		groupSearchDN, err := ldap.CanonicalizeDN(groupSearchDNValue)
		if err != nil {
			return nil, fmt.Errorf("error parsing group-search-dn: %w", err)
		}
		rv.GroupSearchDN = groupSearchDN
	} else {
		rv.GroupSearchDN = rv.BaseDN
	}

	if roleSearchDNValue := v.GetString(roleSearchDNField.FieldName); roleSearchDNValue != "" {
		roleSearchDN, err := ldap.CanonicalizeDN(roleSearchDNValue)
		if err != nil {
			return nil, fmt.Errorf("error parsing role-search-dn: %w", err)
		}
		rv.RoleSearchDN = roleSearchDN
	} else {
		rv.RoleSearchDN = rv.BaseDN
	}

	rv.BindPassword = v.GetString(passwordField.FieldName)
	if rv.BindPassword == "" {
		l.Warn("No password supplied. Will try an unauthenticated bind")
	}

	rv.Filter = v.GetString(filterField.FieldName)

	rv.InsecureSkipVerify = v.GetBool(insecureSkipVerifyField.FieldName)
	rv.DisableOperationalAttrs = v.GetBool(disableOperationalAttrsField.FieldName)

	userStatusAttributes, err := normalizeUserStatusAttributes(v)
	if err != nil {
		return nil, err
	}
	rv.UserStatusAttributes = userStatusAttributes

	l.Info("baton-ldap: user status attribute definition",
		zap.Strings("managed_attributes", userStatusAttributes.ManagedAttributes()),
		zap.Any("disable_user_attributes", userStatusAttributes.Disabled),
		zap.Any("enable_user_attributes", userStatusAttributes.Enabled))

	return rv, nil
}

// UserStatusAttributes is the normalized definition of which LDAP attribute
// values mean that a user account is disabled, and which mean it is enabled.
// Both maps are keyed by literal LDAP attribute name; comparisons against
// directory values are case-insensitive and whitespace-trimmed.
type UserStatusAttributes struct {
	// Disabled maps an LDAP attribute name to the value that marks an account
	// as disabled.
	Disabled map[string]string
	// Enabled maps an LDAP attribute name to the value that marks an account as
	// enabled.
	Enabled map[string]string
}

// ManagedAttributes returns the sorted, case-insensitively deduplicated union
// of the attribute names configured in either direction. It is what the status
// read walks (so a value typo in one entry is still reported when another entry
// decided the status) and what the startup log prints; it deliberately does not
// drive the write path, which applies only the invoked direction's own keys.
func (a UserStatusAttributes) ManagedAttributes() []string {
	seen := make(map[string]bool, len(a.Disabled)+len(a.Enabled))
	var out []string
	for _, attrs := range []map[string]string{a.Disabled, a.Enabled} {
		for name := range attrs {
			lower := strings.ToLower(name)
			if seen[lower] {
				continue
			}
			seen[lower] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// DisabledValue returns the value configured to mark attr as disabled, matching
// the attribute name case-insensitively (LDAP attribute names are). It reports
// false when attr is not configured in that direction, which is expected for a
// disable-only or enable-only definition.
func (a UserStatusAttributes) DisabledValue(attr string) (string, bool) {
	return lookupAttributeFold(a.Disabled, attr)
}

// EnabledValue is DisabledValue for the enabled direction.
func (a UserStatusAttributes) EnabledValue(attr string) (string, bool) {
	return lookupAttributeFold(a.Enabled, attr)
}

// ldapObjectClassAttr is the one attribute name that can never carry the
// enable/disable marker.
const ldapObjectClassAttr = "objectClass"

// normalizeUserStatusAttributes reads both user status attribute maps from the
// connector configuration and validates them.
//
// The validation is a pair with the write path's direction isolation:
// disable_user writes only disable-user-attributes and enable_user only
// enable-user-attributes, so an attribute named in one direction and missing
// from the other would be left at its disabled value by enable_user while the
// read path (union, any-disabled-wins) kept reporting the account as disabled
// forever -- an action result that contradicts the synced state. Requiring the
// same attribute names whenever both directions are configured makes the two
// agree. "Clear on enable" stays expressible as an explicit empty value.
func normalizeUserStatusAttributes(v *viper.Viper) (UserStatusAttributes, error) {
	disabled, err := readAttributeMapField(v, disableUserAttributesField.FieldName)
	if err != nil {
		return UserStatusAttributes{}, err
	}
	enabled, err := readAttributeMapField(v, enableUserAttributesField.FieldName)
	if err != nil {
		return UserStatusAttributes{}, err
	}

	// An empty value on the DISABLE side is self-contradictory. The read path
	// decides DISABLED only from a value that MATCHES the configured disabled
	// value, so an absent attribute can never mean disabled -- configuredUserStatus
	// skips an attribute with no values. "Disable by clearing the marker" would
	// therefore clear the attribute, return success with status=disabled, and
	// leave sync reporting the account enabled forever: exactly the
	// action-vs-synced-state contradiction the symmetry check below exists to
	// prevent. Empty stays legal on the ENABLE side, where "clear on enable" is
	// meaningful and reads as enabled by fall-through.
	//
	// This is also the backstop for the SDK's value coercion. The configuration
	// loader round-trips these maps through cast.ToStringMapString before
	// config.New runs, which stringifies every value and discards the error: a
	// non-string JSON value such as {"revoke":true} or {"revoke":null} arrives
	// here as "", and an unquoted YAML TRUE arrives as the string "true". The
	// empty case is the dangerous one -- left alone it would silently turn a
	// disable into a clear -- and rejecting it here converts that into a startup
	// failure.
	// Collected and sorted rather than returned from inside the loop: Go
	// randomizes map iteration, so an early return would name an arbitrary one
	// of several empty attributes and the operator would have to boot again to
	// discover the next. missingAttributesFold below sorts for the same reason.
	var emptyDisabled []string
	for name, disabledValue := range disabled {
		if disabledValue == "" {
			emptyDisabled = append(emptyDisabled, name)
		}
	}
	if len(emptyDisabled) > 0 {
		sort.Strings(emptyDisabled)
		return UserStatusAttributes{}, fmt.Errorf(
			"%s: attribute(s) %s are configured with an empty value; an empty value cannot mark an account "+
				"disabled, because an absent attribute reads as enabled. Use a value, or put the empty value on "+
				"%s to clear the marker when enabling",
			disableUserAttributesField.FieldName, strings.Join(emptyDisabled, ", "), enableUserAttributesField.FieldName)
	}

	for name, disabledValue := range disabled {
		enabledValue, ok := lookupAttributeFold(enabled, name)
		if !ok {
			continue
		}
		// The same value cannot distinguish the two states: the read path would
		// answer DISABLED for every account. This also covers an attribute left
		// empty in both maps, since an empty value can never mark either state.
		if strings.EqualFold(strings.TrimSpace(disabledValue), strings.TrimSpace(enabledValue)) {
			return UserStatusAttributes{}, fmt.Errorf(
				"%s and %s: attribute %q is configured with the same value for both directions; "+
					"an attribute cannot mean both disabled and enabled",
				disableUserAttributesField.FieldName, enableUserAttributesField.FieldName, name)
		}
	}

	if len(disabled) > 0 && len(enabled) > 0 {
		for _, direction := range []struct {
			field  string
			attrs  map[string]string
			other  map[string]string
			otherF string
		}{
			{disableUserAttributesField.FieldName, disabled, enabled, enableUserAttributesField.FieldName},
			{enableUserAttributesField.FieldName, enabled, disabled, disableUserAttributesField.FieldName},
		} {
			for _, name := range missingAttributesFold(direction.attrs, direction.other) {
				return UserStatusAttributes{}, fmt.Errorf(
					"%s and %s: attribute %q is configured for %s only; both directions must name the same attributes "+
						"(use an empty value to clear it in the other direction)",
					direction.field, direction.otherF, name, direction.field)
			}
		}
	}

	return UserStatusAttributes{Disabled: disabled, Enabled: enabled}, nil
}

// readAttributeMapField reads one attribute-map configuration field and hands
// it to normalizeAttributeMap.
//
// It deliberately does not use v.GetStringMapString. That goes through
// cast.ToStringMapString, which discards its parse error and accepts only five
// concrete types: a call of it against a value it does not recognize returns an
// empty map and a nil error, which is indistinguishable from "not configured".
// Everything downstream then passes trivially -- nothing configured is nothing
// invalid -- and the corresponding action is silently never registered, so the
// connector starts cleanly and does nothing.
//
// Switching on the raw value instead makes each case explicit:
//
//   - nil       -> unconfigured.
//   - string    -> the env-var / inline-string form; parsed as JSON by
//     readAttributeMapString.
//   - map       -> the config-file (map[string]interface{}) and repeated-CLI-flag
//     (map[string]string) forms. Empty means unconfigured.
//   - anything else, and a non-string map value, is an error rather than a
//     guess.
//
// Which case is reachable depends on the shape of the value, and the SDK's
// configuration loader decides it before config.New runs. Measured against the
// running binary rather than inferred:
//
//   - A config-file value that is NESTED -- a list, or a map where a scalar was
//     meant -- reaches this branch unchanged, because cli.VisitFlags skips its
//     cast-based stringToString pass when hasNestedStringMapValue reports a
//     nested value. `revoke: [Y]` and `revoke: {a: b}` both fail here with the
//     offending type named.
//   - A config-file value that is a scalar of the wrong type does NOT: cast
//     stringifies it first, so an unquoted `revoke: TRUE` arrives as the string
//     "true", indistinguishable from a quoted "true", is written that way, and
//     is rejected by the directory at action time. Documented in the README
//     rather than caught here.
//   - A JSON env var holding a non-string does NOT either: cast's JSON decode
//     into map[string]string allocates the key, fails on the value, and cast
//     discards that error -- so {"revoke":true} resolves to {"revoke":""}. That
//     "" is the coercion's dangerous output, which is why an empty value on the
//     disable side is rejected at startup instead.
//
// So this branch is load-bearing for nested values, not dead code.
//
// Empty forms must be recognized explicitly rather than inferred, because
// getting it wrong here is not a degraded feature but a failed boot: config.New
// runs before the connector is built, so it takes user, group and role sync down
// with the lifecycle actions.
func readAttributeMapField(v *viper.Viper, name string) (map[string]string, error) {
	switch raw := v.Get(name).(type) {
	case nil:
		return nil, nil
	case string:
		return readAttributeMapString(name, raw)
	case map[string]string:
		return normalizeAttributeMap(name, raw)
	case map[string]interface{}:
		out := make(map[string]string, len(raw))
		for key, value := range raw {
			str, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf(
					"%s: attribute %q has a %T value (%v); values must be strings, so quote it "+
						"(an unquoted TRUE/FALSE is read as a YAML boolean, and a list or map is not a value at all)",
					name, key, value, value)
			}
			out[key] = str
		}
		return normalizeAttributeMap(name, out)
	default:
		return nil, fmt.Errorf("%s: expected a map of attribute name to value, got %T", name, raw)
	}
}

// readAttributeMapString parses the string form of an attribute map -- what an
// environment variable, or an inline YAML string, arrives as.
//
// The parse is done here rather than trusted from cast because cast discards its
// error: an unparseable string and a valid but empty JSON object both come back
// as an empty map, and only the raw string distinguishes them. An empty object
// is unconfigured; anything that is not a JSON object at all is an error.
func readAttributeMapString(name, raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	var parsed map[string]string
	if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
		// "{}" lands here and normalizeAttributeMap maps it to unconfigured.
		return normalizeAttributeMap(name, parsed)
	}

	// Name the env var exactly as the SDK binds it: the "baton" prefix plus the
	// - to _ replacer. Pointing at an unprefixed name would send an operator who
	// copies it straight back into the silent no-op this error exists to
	// eliminate.
	envName := "BATON_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	return nil, fmt.Errorf(
		"%s: %q is not a valid attribute map; expected a JSON object of attribute name to string value, a YAML map, "+
			"or repeated --%s key=value flags (an environment variable must be JSON, for example %s='{\"revoke\":\"Y\"}')",
		name, raw, name, envName)
}

// normalizeAttributeMap trims attribute names, rejects the names that can never
// be written as an enable/disable marker, and rejects two entries that fold to
// the same attribute name (LDAP attribute names are case-insensitive). Values
// are preserved verbatim: they are compared case-insensitively later, but what
// is written must be what the operator configured.
func normalizeAttributeMap(fieldName string, raw map[string]string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(raw))
	seen := make(map[string]string, len(raw))
	for name, value := range raw {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			return nil, fmt.Errorf("%s: LDAP attribute names must not be empty", fieldName)
		}
		if strings.Contains(strings.ToLower(trimmed), "password") {
			return nil, fmt.Errorf("%s: attribute %q cannot be used to mark an account enabled or disabled; use credential rotation instead", fieldName, trimmed)
		}
		if strings.EqualFold(trimmed, ldapObjectClassAttr) {
			return nil, fmt.Errorf("%s: attribute %q cannot be used to mark an account enabled or disabled", fieldName, trimmed)
		}
		lower := strings.ToLower(trimmed)
		if first, dup := seen[lower]; dup {
			return nil, fmt.Errorf("%s: attribute %q is configured more than once (%q and %q; LDAP attribute names are case-insensitive)", fieldName, trimmed, first, trimmed)
		}
		seen[lower] = trimmed
		out[trimmed] = value
	}
	return out, nil
}

// lookupAttributeFold returns the value configured for name in attrs, matching
// the attribute name case-insensitively.
func lookupAttributeFold(attrs map[string]string, name string) (string, bool) {
	if value, ok := attrs[name]; ok {
		return value, true
	}
	lower := strings.ToLower(name)
	for candidate, value := range attrs {
		if strings.ToLower(candidate) == lower {
			return value, true
		}
	}
	return "", false
}

// missingAttributesFold returns the names configured in attrs that have no
// case-insensitive counterpart in other, sorted for a stable error message.
func missingAttributesFold(attrs, other map[string]string) []string {
	var missing []string
	for name := range attrs {
		if _, ok := lookupAttributeFold(other, name); !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

type Config struct {
	ServerURL *url.URL
	BaseDN    *ldap3.DN

	BindPassword string
	BindDN       *ldap3.DN

	UserSearchDN  *ldap3.DN
	GroupSearchDN *ldap3.DN
	RoleSearchDN  *ldap3.DN

	Filter string

	DisableOperationalAttrs bool
	InsecureSkipVerify      bool

	UserStatusAttributes UserStatusAttributes
}
