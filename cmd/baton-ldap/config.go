package main

import (
	"context"
	"fmt"
	"net/url"

	configschema "github.com/conductorone/baton-sdk/pkg/config"
	"github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
)

var (
	//revive:disable-next-line:line-length-limit
	disableOperationalAttrsField = configschema.BoolField("disable-operational-attrs", configschema.WithDescription("Disable fetching operational attributes. Some LDAP servers don't support these. If disabled, created_at and last login info will not be fetched"))
	urlfield                     = configschema.StringField("url", configschema.WithDescription(`The URL to connect to. Example: "ldaps://baton.example.com"`))
	domainField                  = configschema.StringField("domain", configschema.WithDescription(`The fully-qualified LDAP domain to connect to. Example: "baton.example.com"`))
	baseDNField                  = configschema.StringField("base-dn", configschema.WithDescription(`The base DN to search from. Example: "DC=baton,DC=example,DC=com"`))
	passwordField                = configschema.StringField("password", configschema.WithDescription("The password to bind to the LDAP server"))
	userDNField                  = configschema.StringField("user-dn", configschema.WithDescription("The user DN to bind to the LDAP server"))
	insecureSkipVerifyField      = configschema.BoolField("insecure-skip-verify", configschema.WithDescription("If connecting over TLS, skip verifying the server certificate"))
)

// configurationFields defines the external configuration required for the connector to run.
var configurationFields = []configschema.SchemaField{
	urlfield,
	domainField,
	baseDNField,
	passwordField,
	userDNField,
	insecureSkipVerifyField,
	disableOperationalAttrsField,
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, v *viper.Viper) error {
	l := ctxzap.Extract(ctx)

	domain := v.GetString(domainField.FieldName)
	urlstr := v.GetString(urlfield.FieldName)
	if domain == "" && urlstr == "" {
		return fmt.Errorf("domain or url is required")
	}

	if domain != "" && urlstr != "" {
		return fmt.Errorf("only one of domain or url is allowed")
	}

	if urlstr != "" {
		_, err := url.Parse(urlstr)
		if err != nil {
			return fmt.Errorf("error parsing url: %w", err)
		}
	}

	_, err := ldap.ParseDN(v.GetString(baseDNField.FieldName))
	if err != nil {
		return err
	}

	_, err = ldap.ParseDN(v.GetString(userDNField.FieldName))
	if err != nil {
		return err
	}

	if v.GetString(passwordField.FieldName) == "" {
		l.Warn("No password supplied. Will do unauthenticated binding.")
	}

	return nil
}
