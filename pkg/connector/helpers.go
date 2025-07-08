package connector

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
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

func extractProfile(ctx context.Context, accountInfo *v2.AccountInfo) (string, []ldap.Attribute, error) {
	l := ctxzap.Extract(ctx)

	name := accountInfo.GetLogin()

	prof := accountInfo.GetProfile()
	if prof == nil {
		return "", nil, fmt.Errorf("missing profile")
	}
	data := prof.AsMap()
	l.Debug("baton-ldap: create-account profile", zap.Any("data", data))

	suffix, ok := data["suffix"].(string)
	if !ok {
		return "", nil, fmt.Errorf("invalid/missing suffix")
	}
	path, ok := data["path"].(string)
	if !ok {
		return "", nil, fmt.Errorf("invalid/missing path")
	}
	rdnKey, ok := data["rdnKey"].(string)
	if !ok {
		return "", nil, fmt.Errorf("invalid/missing rdnKey")
	}

	var dn string
	if path != "" {
		dn = strings.Join([]string{fmt.Sprintf("%s=%s", rdnKey, name), path, suffix}, ",")
	} else {
		dn = strings.Join([]string{fmt.Sprintf("%s=%s", rdnKey, name), suffix}, ",")
	}

	objectClass, ok := data["objectClass"].([]any)
	if !ok {
		return "", nil, fmt.Errorf("invalid/missing objectClass")
	}
	for _, oc := range objectClass {
		if _, ok := oc.(string); !ok {
			return "", nil, fmt.Errorf("invalid objectClass")
		}
	}

	attrs := []ldap.Attribute{}

	for k, v := range data {
		if slices.Contains([]string{
			"additionalAttributes",
			"rdnKey",
			"path",
			"suffix",
			"login",
		}, k) {
			continue
		}
		attrs = append(attrs, toAttr(k, v))
	}

	additionalAttributes, ok := data["additionalAttributes"].(map[string]interface{})
	if ok {
		for k, v := range additionalAttributes {
			attrs = append(attrs, toAttr(k, v))
		}
	}

	l.Debug("baton-ldap: create-account attributes", zap.Any("attrs", attrs))

	return dn, attrs, nil
}
