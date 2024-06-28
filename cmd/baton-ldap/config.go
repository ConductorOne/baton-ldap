package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/conductorone/baton-sdk/pkg/cli"
	bconfig "github.com/conductorone/baton-sdk/pkg/config"
	"github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
)

// config defines the external configuration required for the connector to run.
type config struct {
	cli.BaseConfig `mapstructure:",squash"` // Puts the base config options in the same place as the connector options

	Url      string `mapstructure:"url" description:"The URL to connect to. Example: \"ldaps://baton.example.com\""`
	Domain   string `mapstructure:"domain" description:"The fully-qualified LDAP domain to connect to. Example: \"baton.example.com\""`
	BaseDN   string `mapstructure:"base-dn" description:"The base DN to search from. Example: \"DC=baton,DC=example,DC=com\""`
	Password string `mapstructure:"password" description:"The password to bind to the LDAP server."`
	UserDN   string `mapstructure:"user-dn" description:"The user DN to bind to the LDAP server."`
	//revive:disable-next-line:line-length-limit
	DisableOperationalAttrs bool `mapstructure:"disable-operational-attrs" description:"Disable fetching operational attributes. Some LDAP servers don't support these. If disabled, created_at and last login info will not be fetched."`
	InsecureSkipVerify      bool `mapstructure:"insecure-skip-verify" description:"If connecting over TLS, skip verifying the server certificate."`
}

type LdapCfg struct {
	bconfig.BaseConfig
	Url                     *bconfig.StringField
	Domain                  *bconfig.StringField
	BaseDN                  *bconfig.StringField
	Password                *bconfig.StringField
	UserDN                  *bconfig.StringField
	DisableOperationalAttrs *bconfig.BoolField
	InsecureSkipVerify      *bconfig.BoolField
}

var cfg = &LdapCfg{
	Url:                     bconfig.NewStringField("url", "The URL to connect to. Example: \"ldaps://baton.example.com\"", false, ""),
	Domain:                  bconfig.NewStringField("domain", "The fully-qualified LDAP domain to connect to. Example: \"baton.example.com\"", false, ""),
	BaseDN:                  bconfig.NewStringField("base-dn", "The base DN to search from. Example: \"DC=baton,DC=example,DC=com\"", false, ""),
	Password:                bconfig.NewStringField("password", "The password to bind to the LDAP server.", false, ""),
	UserDN:                  bconfig.NewStringField("user-dn", "The user DN to bind to the LDAP server.", false, ""),
	DisableOperationalAttrs: bconfig.NewBoolField("disable-operational-attrs", "Disable fetching operational attributes. Some LDAP servers don't support these. If disabled, created_at and last login info will not be fetched.", false, false),
	InsecureSkipVerify:      bconfig.NewBoolField("insecure-skip-verify", "If connecting over TLS, skip verifying the server certificate.", false, false),
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, cfg *config) error {
	l := ctxzap.Extract(ctx)

	if cfg.Domain == "" && cfg.Url == "" {
		return fmt.Errorf("domain or url is required")
	}

	if cfg.Domain != "" && cfg.Url != "" {
		return fmt.Errorf("only one of domain or url is allowed")
	}

	if cfg.Url != "" {
		_, err := url.Parse(cfg.Url)
		if err != nil {
			return fmt.Errorf("error parsing url: %w", err)
		}
	}

	_, err := ldap.ParseDN(cfg.BaseDN)
	if err != nil {
		return err
	}

	_, err = ldap.ParseDN(cfg.UserDN)
	if err != nil {
		return err
	}

	if cfg.Password == "" {
		l.Warn("No password supplied. Will do unauthenticated binding.")
	}

	return nil
}
