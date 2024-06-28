package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-ldap/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

var version = "dev"

func main() {
	ctx := context.Background()

	// cfg := &config{}
	cmd, err := cli.NewCmd2(ctx, "baton-ldap", cfg, validateConfig, getConnector)

	// cmd, err := cli.NewCmd(ctx, "baton-ldap", cfg, validateConfig, getConnector)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version

	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, cfg *LdapCfg) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)

	if cfg.Url.Value() == "" && cfg.Domain.Value() != "" {
		cfg.Url = fmt.Sprintf("ldap://%s", cfg.Domain)
	}

	ldapConnector, err := connector.New(ctx, cfg.Url, cfg.BaseDN, cfg.Password, cfg.UserDN, cfg.DisableOperationalAttrs, cfg.InsecureSkipVerify)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	c, err := connectorbuilder.NewConnector(ctx, ldapConnector)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	return c, nil
}
