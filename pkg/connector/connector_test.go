package connector

import (
	"context"
	"os"
	"path/filepath"

	"embed"
	"net/url"
	"testing"

	"github.com/conductorone/baton-ldap/pkg/config"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/openldap"

	_ "embed"
)

//go:embed testfixtures/*.ldif
var fixtures embed.FS

func TestValidate(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()

	connector, err := createConnector(ctx, t, "")
	require.NoError(t, err)

	_, err = connector.Validate(ctx)
	require.NoError(t, err)
}

func createConnector(ctx context.Context, t *testing.T, fixtureName string) (*LDAP, error) {
	opts := []testcontainers.ContainerCustomizer{
		openldap.WithAdminUsername("admin"),
		openldap.WithAdminPassword("hunter2"),
	}

	if fixtureName != "" {
		data, err := fixtures.ReadFile(filepath.Join("testfixtures", fixtureName))
		if err != nil {
			return nil, err
		}
		fd, err := os.CreateTemp("", "ldif")
		if err != nil {
			return nil, err
		}
		fdPath := fd.Name()
		fd.Close()
		t.Cleanup(func() {
			os.Remove(fdPath)
		})

		err = os.WriteFile(fdPath, data, 0600)
		if err != nil {
			return nil, err
		}
		opts = append(opts, openldap.WithInitialLdif(fdPath))
	}

	container, err := openldap.Run(ctx,
		"bitnami/openldap:2.6.6",
		opts...,
	)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		require.NoError(t, container.Terminate(context.Background()))
	})

	serverURL, err := container.ConnectionString(ctx)
	if err != nil {
		return nil, err
	}

	sux, err := url.Parse(serverURL)
	if err != nil {
		return nil, err
	}

	bindDN, err := ldap.ParseDN("cn=admin,dc=example,dc=org")
	if err != nil {
		return nil, err
	}

	cf := &config.Config{
		ServerURL:     sux,
		BindDN:        bindDN,
		BaseDN:        mustParseDN(t, "dc=example,dc=org"),
		GroupSearchDN: mustParseDN(t, "ou=groups,dc=example,dc=org"),
		UserSearchDN:  mustParseDN(t, "ou=users,dc=example,dc=org"),
		BindPassword:  "hunter2",
	}
	return New(ctx, cf)
}

func mustParseDN(t *testing.T, input string) *ldap.DN {
	dn, err := ldap.ParseDN(input)
	require.NoError(t, err)
	return dn
}
