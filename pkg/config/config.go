package config

import (
	"context"
	"fmt"
	"net/url"

	"github.com/conductorone/baton-ldap/pkg/ldap"
	"github.com/conductorone/baton-sdk/pkg/field"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
)

var (
	urlField = field.StringField("url", field.WithDescription(`The URL to connect to. Example: "ldaps://baton.example.com"`))

	baseDNField   = field.StringField("base-dn", field.WithDescription(`The base DN to search from. Example: "DC=baton,DC=example,DC=com"`))
	passwordField = field.StringField("password", field.WithDescription("The password to bind to the LDAP server"))
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

	return rv, nil
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
}
