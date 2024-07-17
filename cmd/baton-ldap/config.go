package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
)

var (
	//revive:disable-next-line:line-length-limit
	disableOperationalAttrsField = field.BoolField("disable-operational-attrs", field.WithDescription("Disable fetching operational attributes. Some LDAP servers don't support these. If disabled, created_at and last login info will not be fetched"))
	urlField                     = field.StringField("url", field.WithDescription(`The URL to connect to. Example: "ldaps://baton.example.com"`))
	domainField                  = field.StringField("domain", field.WithDescription(`The fully-qualified LDAP domain to connect to. Example: "baton.example.com"`))
	baseDNField                  = field.StringField("base-dn", field.WithDescription(`The base DN to search from. Example: "DC=baton,DC=example,DC=com"`))
	passwordField                = field.StringField("password", field.WithDescription("The password to bind to the LDAP server"))
	userDNField                  = field.StringField("user-dn", field.WithDescription("The user DN to bind to the LDAP server"))
	insecureSkipVerifyField      = field.BoolField("insecure-skip-verify", field.WithDescription("If connecting over TLS, skip verifying the server certificate"))
)

// configurationFields defines the external configuration required for the connector to run.
var configurationFields = []field.SchemaField{
	urlField,
	domainField,
	baseDNField,
	passwordField,
	userDNField,
	insecureSkipVerifyField,
	disableOperationalAttrsField,
}

var configRelations = []field.SchemaFieldRelationship{
	field.FieldsMutuallyExclusive(domainField, urlField),
	field.FieldsAtLeastOneUsed(domainField, urlField),
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, v *viper.Viper) error {
	l := ctxzap.Extract(ctx)

	urlstr := v.GetString(urlField.FieldName)
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
