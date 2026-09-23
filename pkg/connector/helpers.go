package connector

import (
	"fmt"
	"strconv"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/go-ldap/ldap/v3"
)

var ResourcesPageSize uint32 = 50

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
func parseValues(entry *ldap.Entry, targetAttrs []string) mapset.Set[string] {
	rv := mapset.NewSet[string]()

	for _, targetAttr := range targetAttrs {
		payload := entry.GetAttributeValues(targetAttr)

		for _, v := range payload {
			rv.Add(v)
		}
	}

	return rv
}

func parseValue(entry *ldap.Entry, targetAttrs []string) string {
	for _, targetAttr := range targetAttrs {
		payload := entry.GetEqualFoldAttributeValue(targetAttr)

		if payload != "" {
			return payload
		}
	}

	return ""
}

// We assume that all values are of the same type.
func toVals(vals []any) []string {
	if len(vals) == 0 {
		return nil
	}

	switch vals[0].(type) {
	case string:
		ret := make([]string, len(vals))
		for i, v := range vals {
			ret[i] = v.(string)
		}
		return ret
	case []byte:
		ret := make([]string, len(vals))
		for i, v := range vals {
			ret[i] = string(v.([]byte))
		}
		return ret
	default:
		ret := make([]string, len(vals))
		for i, v := range vals {
			ret[i] = fmt.Sprintf("%v", v)
		}
		return ret
	}
}

func toAttr(k string, v interface{}) ldap.Attribute {
	switch v := v.(type) {
	case []string:
		return ldap.Attribute{
			Type: k,
			Vals: v,
		}
	case []any:
		return ldap.Attribute{
			Type: k,
			Vals: toVals(v),
		}
	case string:
		return ldap.Attribute{
			Type: k,
			Vals: []string{v},
		}
	case []byte:
		return ldap.Attribute{
			Type: k,
			Vals: []string{string(v)},
		}
	case bool:
		return ldap.Attribute{
			Type: k,
			Vals: []string{strconv.FormatBool(v)},
		}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return ldap.Attribute{
			Type: k,
			Vals: []string{fmt.Sprintf("%d", v)},
		}
	case float32, float64:
		return ldap.Attribute{
			Type: k,
			Vals: []string{fmt.Sprintf("%f", v)},
		}
	default:
		// l.Warn("unsupported attribute type", zap.Any("type", v))
		return ldap.Attribute{
			Type: k,
			Vals: []string{fmt.Sprintf("%v", v)},
		}
	}
}

// toAttrIfNotEmpty returns the LDAP attribute for a profile value and reports
// whether it may be sent at all. It is the create-account rule: a value the
// profile left unset must produce no attribute, because an LDAP Add carrying
// one is rejected outright on a Directory String attribute (result 21,
// "Invalid Attribute Syntax") and accepted-but-stored on an IA5 String one
// (mail). A create-account profile carries no syntax information, so the
// connector cannot tell the two apart, and the create-account task is not
// retryable.
//
// A value is dropped when it is nil, the empty string, a zero-length []byte, or
// a list with no usable entry. nil is dropped rather than converted because
// toAttr's default branch renders it as the literal "<nil>", which the
// directory accepts and stores -- turning a loud failure into silent bad data.
// Non-string scalars (false, 0) are real values and are kept.
//
// update_profile is the opposite rule -- there an empty value means "remove the
// attribute" (see buildUserAttrChanges) -- so this helper belongs to the create
// path only and must not be reused there.
func toAttrIfNotEmpty(k string, v any) (ldap.Attribute, bool) {
	switch val := v.(type) {
	case nil:
		return ldap.Attribute{}, false
	case string:
		if val == "" {
			return ldap.Attribute{}, false
		}
	case []byte:
		if len(val) == 0 {
			return ldap.Attribute{}, false
		}
	case []string:
		vals := nonEmptyStrings(val)
		if len(vals) == 0 {
			return ldap.Attribute{}, false
		}
		return ldap.Attribute{Type: k, Vals: vals}, true
	case []any:
		vals := nonEmptyVals(val)
		if len(vals) == 0 {
			return ldap.Attribute{}, false
		}
		return ldap.Attribute{Type: k, Vals: vals}, true
	}

	return toAttr(k, v), true
}

// nonEmptyStrings returns vals without its empty entries. The result is nil
// when nothing is left.
func nonEmptyStrings(vals []string) []string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// nonEmptyVals returns the string values of vals without the entries that must
// not become an LDAP value: nil (which toVals would render as the literal
// "<nil>") and elements that render to the empty string. Rendering is delegated
// to toVals/toAttr, so a kept entry keeps the exact form toAttr would have given
// it. The result is nil when nothing is left.
func nonEmptyVals(vals []any) []string {
	kept := make([]any, 0, len(vals))
	for _, v := range vals {
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		kept = append(kept, v)
	}
	if len(kept) == 0 {
		return nil
	}

	return nonEmptyStrings(toVals(kept))
}
