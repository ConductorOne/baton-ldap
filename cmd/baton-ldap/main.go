package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-ldap/pkg/connector"
	configschema "github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var version = "dev"

func main() {
	ctx := context.Background()

	_, cmd, err := configschema.DefineConfiguration(ctx, "baton-ldap", getConnector, configurationFields, configRelations)
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

func getConnector(ctx context.Context, v *viper.Viper) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)

	if err := validateConfig(ctx, v); err != nil {
		return nil, err
	}

	if v.GetString(urlField.FieldName) == "" && v.GetString(domainField.FieldName) != "" {
		v.Set(urlField.FieldName, fmt.Sprintf("ldap://%s", v.GetString(domainField.FieldName)))
	}

	ldapConnector, err := connector.New(
		ctx,
		v.GetString(urlField.FieldName),
		v.GetString(baseDNField.FieldName),
		v.GetString(passwordField.FieldName),
		v.GetString(userDNField.FieldName),
		v.GetBool(disableOperationalAttrsField.FieldName),
		v.GetBool(insecureSkipVerifyField.FieldName),
	)
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
