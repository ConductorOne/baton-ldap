package ldap

import (
	"strings"

	ldap3 "github.com/go-ldap/ldap/v3"
)

// List of attribute types whose values should be made lowercase
var caseInsensitiveAttrs = map[string]bool{
	"cn":              true,
	"uid":             true,
	"ou":              true,
	"dc":              true,
	"sn":              true,
	"givenname":       true,
	"mail":            true,
	"member":          true,
	"memberof":        true,
	"o":               true,
	"c":               true,
	"l":               true,
	"st":              true,
	"telephonenumber": true,
	"description":     true,
}

// CanonicalizeDN takes a distinguished name (DN) and canonicalizes it by standardizing the case of attributes and values.
func CanonicalizeDN(dn string) (*ldap3.DN, error) {
	dnv, err := ldap3.ParseDN(dn)
	if err != nil {
		return nil, err
	}

	for _, rdn := range dnv.RDNs {
		for _, attr := range rdn.Attributes {
			attr.Type = strings.ToLower(attr.Type)
			attr.Value = strings.TrimSpace(attr.Value)
			if caseInsensitiveAttrs[attr.Type] {
				attr.Value = strings.ToLower(attr.Value)
			}
		}
	}

	return dnv, nil
}
