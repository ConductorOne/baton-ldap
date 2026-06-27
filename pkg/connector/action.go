package connector

import (
	"fmt"
	"strings"

	"github.com/conductorone/baton-ldap/pkg/ldap"
	ldap3 "github.com/go-ldap/ldap/v3"
)

const (
	ldapObjectClassOU = "organizationalUnit"
	ldapAttrOU        = "ou"
)

// buildOUDN validates the OU name and parent, enforces the fail-closed base-dn
// scope check, and returns the fully-qualified DN for the new OU
// (ou=<escaped-name>,<canonical-parent>). Returned errors are lowercase
// fragments; callers add the connector prefix.
func buildOUDN(name, parentDN string, baseDN *ldap3.DN) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if baseDN == nil {
		return "", fmt.Errorf("base-dn must be configured")
	}
	// Don't assume the stored BaseDN is canonical (the test harness builds it via
	// raw ParseDN); canonicalize so the comparison and the rejection message use
	// normalized values.
	canonBase, err := ldap.CanonicalizeDN(baseDN.String())
	if err != nil {
		return "", fmt.Errorf("invalid base-dn %q: %w", baseDN.String(), err)
	}
	baseDN = canonBase

	parentDN = strings.TrimSpace(parentDN)
	parent := baseDN
	if parentDN != "" {
		p, err := ldap.CanonicalizeDN(parentDN)
		if err != nil {
			return "", fmt.Errorf("invalid parent_dn %q: %w", parentDN, err)
		}
		parent = p
	}

	if !baseDN.EqualFold(parent) && !baseDN.AncestorOfFold(parent) {
		return "", fmt.Errorf("parent_dn %q is outside the configured base-dn %q", parent.String(), baseDN.String())
	}

	return fmt.Sprintf("%s=%s,%s", ldapAttrOU, ldap3.EscapeDN(name), parent.String()), nil
}
