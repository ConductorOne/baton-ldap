package connector

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
)

func TestParseDN(t *testing.T) {
	dn, err := ldap.ParseDN("cn=test,ou=test,dc=example,dc=com")
	require.NoError(t, err)
	require.Equal(t, "cn=test,ou=test,dc=example,dc=com", dn.String())

	dn, err = ldap.ParseDN("dc=example,dc=com")
	require.NoError(t, err)
	require.Equal(t, "dc=example,dc=com", dn.String())

	dn, err = ldap.ParseDN("ou=example")
	require.NoError(t, err)
	require.Equal(t, "ou=example", dn.String())
}
