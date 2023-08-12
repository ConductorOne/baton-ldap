package connector

import (
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"google.golang.org/protobuf/types/known/structpb"
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

// Parses the member ids of a role or a group.
func parseMembers(entry *ldap.Entry, targetAttr string) ([]string, error) {
	membersPayload := entry.GetAttributeValues(targetAttr)

	if len(membersPayload) == 0 {
		return nil, nil
	}

	return membersPayload, nil
}

func containsMember(memberEntries []string, memberId string) bool {
	for _, m := range memberEntries {
		if m == memberId {
			return true
		}
	}

	return false
}

func removeMember(memberEntries []string, memberId string) ([]string, error) {
	updatedEntries := make([]string, 0, len(memberEntries)-1)

	for _, entry := range memberEntries {
		if entry != memberId {
			updatedEntries = append(updatedEntries, entry)
		}
	}

	return updatedEntries, nil
}

func addMember(memberEntries []string, entry string) []string {
	return append(memberEntries, entry)
}

func GetProfileStringArray(profile *structpb.Struct, k string) ([]string, bool) {
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

func StringSliceToInterfaceSlice(s []string) []interface{} {
	var i []interface{}
	for _, v := range s {
		i = append(i, v)
	}
	return i
}
