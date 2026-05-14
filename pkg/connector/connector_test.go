package connector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"embed"
	"net/url"
	"testing"

	"github.com/conductorone/baton-ldap/pkg/config"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/openldap"
)

//go:embed testfixtures/*.ldif
var fixtures embed.FS

func TestValidate(t *testing.T) {
	ctx := t.Context()

	connector, err := createConnector(ctx, t, "")
	require.NoError(t, err)

	_, err = connector.Validate(ctx)
	require.NoError(t, err)
}

func createConnector(ctx context.Context, t *testing.T, fixtureName string, extraOpts ...testcontainers.ContainerCustomizer) (*LDAP, error) {
	c, _, err := createConnectorWithContainer(ctx, t, fixtureName, extraOpts...)
	return c, err
}

func createConnectorWithContainer(ctx context.Context, t *testing.T, fixtureName string, extraOpts ...testcontainers.ContainerCustomizer) (*LDAP, *openldap.OpenLDAPContainer, error) {
	opts := []testcontainers.ContainerCustomizer{
		openldap.WithAdminUsername("admin"),
		openldap.WithAdminPassword("hunter2"),
	}
	opts = append(opts, extraOpts...)

	if fixtureName != "" {
		data, err := fixtures.ReadFile(filepath.Join("testfixtures", fixtureName))
		if err != nil {
			return nil, nil, err
		}
		fd, err := os.CreateTemp("", "ldif")
		if err != nil {
			return nil, nil, err
		}
		fdPath := fd.Name()
		t.Cleanup(func() {
			_ = os.Remove(fdPath)
		})

		n, err := fd.Write(data)
		if err != nil {
			return nil, nil, err
		}
		if n != len(data) {
			return nil, nil, fmt.Errorf("short write: wrote %d bytes, expected %d", n, len(data))
		}
		if cerr := fd.Close(); cerr != nil {
			return nil, nil, cerr
		}
		opts = append(opts, openldap.WithInitialLdif(fdPath))
	}

	container, err := openldap.Run(ctx,
		"bitnamilegacy/openldap:2.6.6",
		opts...,
	)
	if err != nil {
		return nil, nil, err
	}
	t.Cleanup(func() {
		require.NoError(t, container.Terminate(context.Background()))
	})

	serverURL, err := container.ConnectionString(ctx)
	if err != nil {
		return nil, nil, err
	}

	sux, err := url.Parse(serverURL)
	if err != nil {
		return nil, nil, err
	}

	cf := &config.Config{
		ServerURL:     sux,
		BindDN:        mustParseDN(t, "cn=admin,dc=example,dc=org"),
		BaseDN:        mustParseDN(t, "dc=example,dc=org"),
		GroupSearchDN: mustParseDN(t, "ou=groups,dc=example,dc=org"),
		UserSearchDN:  mustParseDN(t, "ou=users,dc=example,dc=org"),
		RoleSearchDN:  mustParseDN(t, "ou=roles,dc=example,dc=org"),
		BindPassword:  "hunter2",
	}
	c, err := New(ctx, cf)
	if err != nil {
		return nil, nil, err
	}
	return c, container, nil
}

// setupDyngroupTest starts a container with the base dynamic-group fixture,
// loads the dyngroup schema via root exec, and adds the groupOfURLs entry.
func setupDyngroupTest(ctx context.Context, t *testing.T) (*LDAP, error) {
	connector, container, err := createConnectorWithContainer(ctx, t, "dynamic_groups_base.ldif")
	if err != nil {
		return nil, err
	}

	// Run as the bitnami container user (UID 1001) — that's what bitnami's cn=config ACL grants manage access to.
	exitCode, _, err := container.Exec(ctx,
		[]string{"ldapadd", "-Y", "EXTERNAL",
			"-H", "ldapi://%2Fopt%2Fbitnami%2Fopenldap%2Fvar%2Frun%2Fldapi",
			"-f", "/opt/bitnami/openldap/etc/schema/dyngroup.ldif"},
	)
	if err != nil {
		return nil, fmt.Errorf("schema exec: %w", err)
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("dyngroup schema load exited with %d", exitCode)
	}

	addReq := ldap3.NewAddRequest("cn=engineers,ou=groups,dc=example,dc=org", nil)
	addReq.Attribute("objectClass", []string{"groupOfURLs", ldapObjectClassTop})
	addReq.Attribute("cn", []string{"engineers"})
	addReq.Attribute("description", []string{"All engineers (dynamic group)"})
	addReq.Attribute("memberURL", []string{"ldap:///ou=users,dc=example,dc=org??sub?(employeeType=Engineering)"})
	if err := connector.client.LdapAdd(ctx, addReq); err != nil {
		return nil, fmt.Errorf("adding engineers group: %w", err)
	}

	return connector, nil
}

func mustParseDN(t *testing.T, input string) *ldap3.DN {
	dn, err := ldap3.ParseDN(input)
	require.NoError(t, err)
	return dn
}

func pluck[T any](slice []T, fn func(v T) bool) T {
	var emptyT T
	for _, v := range slice {
		if fn(v) {
			return v
		}
	}
	return emptyT
}
