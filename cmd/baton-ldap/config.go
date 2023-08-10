package main

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/go-ldap/ldap/v3"
	"github.com/spf13/cobra"
)

// config defines the external configuration required for the connector to run.
type config struct {
	cli.BaseConfig `mapstructure:",squash"` // Puts the base config options in the same place as the connector options

	Domain   string `mapstructure:"domain"`
	BaseDN   string `mapstructure:"base-dn"`
	Password string `mapstructure:"password"`
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, cfg *config) error {
	if cfg.Domain == "" {
		return fmt.Errorf("domain is required")
	}

	_, err := ldap.ParseDN(cfg.BaseDN)
	if err != nil {
		return err
	}

	if cfg.Password == "" {
		return fmt.Errorf("password is required")
	}

	return nil
}

// cmdFlags sets the cmdFlags required for the connector.
func cmdFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("domain", "", "The fully-qualified LDAP domain to connect with. Example: \"baton.example.com\" ($BATON_DOMAIN)")
	cmd.PersistentFlags().String("base-dn", "", "The base DN to search from. Example: \"DC=baton,DC=example,DC=com\" ($BATON_BASE_DN)")
	cmd.PersistentFlags().String("password", "", "The password to bind to the LDAP server. ($BATON_PASSWORD)")
}
