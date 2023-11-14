package connector

import (
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/go-ldap/ldap/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

var ResourcesPageSize = 50

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

// Parses the values of targetted attributes from an LDAP entry.
func parseValues(entry *ldap.Entry, targetAttrs []string) []string {
	var rv []string

	for _, targetAttr := range targetAttrs {
		payload := entry.GetAttributeValues(targetAttr)

		if len(payload) > 0 {
			rv = append(rv, payload...)
			break
		}
	}

	return rv
}

func parseValue(entry *ldap.Entry, targetAttrs []string) string {
	for _, targetAttr := range targetAttrs {
		payload := entry.GetAttributeValue(targetAttr)

		if payload != "" {
			return payload
		}
	}

	return ""
}

func getProfileStringArray(profile *structpb.Struct, k string) ([]string, bool) {
	var values []string
	if profile == nil {
		return nil, false
	}

	v, ok := profile.Fields[k]
	if !ok {
		return nil, false
	}

	s, ok := v.Kind.(*structpb.Value_ListValue)
	if !ok {
		return nil, false
	}

	for _, v := range s.ListValue.Values {
		if strVal := v.GetStringValue(); strVal != "" {
			values = append(values, strVal)
		}
	}

	return values, true
}

func stringSliceToInterfaceSlice(s []string) []interface{} {
	var i []interface{}
	for _, v := range s {
		i = append(i, v)
	}
	return i
}
