package connector

import (
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var ResourcesPageSize = 50

var titleCaser = cases.Title(language.English)

func annotationsForUserResourceType() annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.SkipEntitlementsAndGrants{})
	return annos
}

func splitFullName(fullName string) (string, string) {
	parts := strings.Split(fullName, " ")

	return parts[0], strings.Join(parts[1:], " ")
}

func parsePageToken(i string, resourceID *v2.ResourceId) (*pagination.Bag, string, error) {
	b := &pagination.Bag{}
	err := b.Unmarshal(i)
	if err != nil {
		return nil, "", err
	}

	if b.Current() == nil {
		b.Push(pagination.PageState{
			ResourceTypeID: resourceID.ResourceType,
			ResourceID:     resourceID.Resource,
		})
	}

	return b, b.PageToken(), nil
}

// Parses the uid from a member entry
// Format of each member is "uid=jdoe,ou=users,dc=example,dc=org".
func parseUID(memberDN string) (string, error) {
	dn, err := ldap.ParseDN(memberDN)
	if err != nil {
		return "", err
	}

	for _, rdn := range dn.RDNs {
		for _, attr := range rdn.Attributes {
			if attr.Type == "uid" {
				return attr.Value, nil
			}
		}
	}

	return "", fmt.Errorf("ldap-connector: failed to parse uid from member DN %s", memberDN)
}

// Parses the member ids of a role or a group.
func parseMembers(role *ldap.Entry, targetAttr string) ([]string, error) {
	membersPayload := role.GetAttributeValues(targetAttr)

	if len(membersPayload) == 0 {
		return nil, nil
	}

	var members []string

	for _, memberDN := range membersPayload {
		uid, err := parseUID(memberDN)
		if err != nil {
			return nil, err
		}

		members = append(members, uid)
	}

	return members, nil
}