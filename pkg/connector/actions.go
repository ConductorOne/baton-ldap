package connector

import (
	"context"
	"fmt"

	config "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
)

// profileAttrToLDAP maps ConductorOne profile field names to their corresponding LDAP attribute names.
// Attributes not in this map are passed through directly, which supports extension attributes
// (e.g., extensionAttribute1-15) and any other custom LDAP attributes.
var profileAttrToLDAP = map[string]string{
	"first_name":      "givenName",
	"last_name":       "sn",
	"display_name":    "displayName",
	"middle_name":     "middleName",
	"job_title":       "title",
	"department":      "department",
	"division":        "division",
	"company":         "company",
	"employee_id":     "employeeID",
	"employee_number": "employeeNumber",
	"employment_type": "employeeType",
	"email":           "mail",
}

// resolveAttrName translates a ConductorOne profile attribute name to the corresponding LDAP attribute name.
// If the name is in the standard mapping, the mapped LDAP name is returned.
// Otherwise, the name is returned as-is, allowing arbitrary LDAP attributes (including extension attributes).
func resolveAttrName(name string) string {
	if ldapName, ok := profileAttrToLDAP[name]; ok {
		return ldapName
	}
	return name
}

var updateUserAttrsActionSchema = &v2.BatonActionSchema{
	Name: "update_user_attrs",
	Arguments: []*config.Field{
		{
			Name:        "resource_type",
			DisplayName: "Resource Type",
			Description: "The type of the resource to update.",
			Field:       &config.Field_StringField{},
			IsRequired:  true,
		},
		{
			Name:        "resource_id",
			DisplayName: "Resource ID",
			Description: "The ID (DN) of the user to update.",
			Field:       &config.Field_StringField{},
			IsRequired:  true,
		},
		{
			Name:        "attrs",
			DisplayName: "Attributes",
			Description: "The updated attribute data. Keys can be standard profile fields (first_name, last_name, etc.) or LDAP attribute names (extensionAttribute1, etc.).",
			Field:       &config.Field_StringMapField{},
			IsRequired:  true,
		},
		{
			Name:        "attrs_update_mask",
			DisplayName: "Attributes Update Mask",
			Description: "The attributes to update.",
			Field:       &config.Field_StringSliceField{},
			IsRequired:  true,
		},
	},
	ReturnTypes: []*config.Field{
		{
			Name:        "success",
			DisplayName: "Success",
			Description: "Whether the account was updated successfully.",
			Field:       &config.Field_BoolField{},
		},
	},
	ActionType: []v2.ActionType{
		v2.ActionType_ACTION_TYPE_ACCOUNT,
		v2.ActionType_ACTION_TYPE_ACCOUNT_UPDATE_PROFILE,
	},
}

func (l *LDAP) GlobalActions(ctx context.Context, registry actions.ActionRegistry) error {
	err := registry.Register(ctx, updateUserAttrsActionSchema, l.updateUserAttributes)
	if err != nil {
		return err
	}
	return nil
}

func (l *LDAP) updateUserAttributes(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	logger := ctxzap.Extract(ctx)

	resourceType, ok := args.Fields["resource_type"]
	if !ok {
		return nil, nil, fmt.Errorf("baton-ldap: missing required argument resource_type")
	}
	if resourceType.GetStringValue() != "user" {
		return nil, nil, fmt.Errorf("baton-ldap: resource type must be user")
	}

	resourceID, ok := args.Fields["resource_id"]
	if !ok {
		return nil, nil, fmt.Errorf("baton-ldap: missing required argument resource_id")
	}
	userDN := resourceID.GetStringValue()
	if userDN == "" {
		return nil, nil, fmt.Errorf("baton-ldap: resource_id cannot be empty")
	}

	attrsField, ok := args.Fields["attrs"]
	if !ok {
		return nil, nil, fmt.Errorf("baton-ldap: missing required argument attrs")
	}
	attrs := make(map[string]string)
	for k, v := range attrsField.GetStructValue().GetFields() {
		attrs[k] = v.GetStringValue()
	}

	attrsUpdateMaskList, ok := args.Fields["attrs_update_mask"]
	if !ok {
		return nil, nil, fmt.Errorf("baton-ldap: missing required argument attrs_update_mask")
	}
	var attrsUpdateMask []string
	for _, v := range attrsUpdateMaskList.GetListValue().GetValues() {
		attrsUpdateMask = append(attrsUpdateMask, v.GetStringValue())
	}

	// Verify the user exists.
	_, err := getAccount(ctx, l.client, userDN)
	if err != nil {
		logger.Error("baton-ldap: update_user_attrs failed to get user", zap.Error(err), zap.String("dn", userDN))
		return nil, nil, fmt.Errorf("baton-ldap: failed to get user %s: %w", userDN, err)
	}

	// Build LDAP modify request from the update mask.
	changes := buildLDAPChanges(logger, attrs, attrsUpdateMask)
	if len(changes) == 0 {
		logger.Info("baton-ldap: update_user_attrs no attributes to update", zap.String("dn", userDN))
		return successResponse(), nil, nil
	}

	modifyRequest := &ldap3.ModifyRequest{
		DN:      userDN,
		Changes: changes,
	}

	logger.Info("baton-ldap: updating user attributes",
		zap.String("dn", userDN),
		zap.Int("num_changes", len(changes)),
	)

	err = l.client.LdapModify(ctx, modifyRequest)
	if err != nil {
		logger.Error("baton-ldap: update_user_attrs failed to modify user", zap.Error(err), zap.String("dn", userDN))
		return nil, nil, fmt.Errorf("baton-ldap: failed to update user %s: %w", userDN, err)
	}

	return successResponse(), nil, nil
}

// buildLDAPChanges creates LDAP modify changes from the attrs map and update mask.
// Each attribute name in the update mask is resolved through the profile-to-LDAP mapping.
// If a value is empty, the attribute is deleted; otherwise it is replaced.
func buildLDAPChanges(l *zap.Logger, attrs map[string]string, updateMask []string) []ldap3.Change {
	var changes []ldap3.Change

	for _, attrName := range updateMask {
		ldapAttrName := resolveAttrName(attrName)
		value, ok := attrs[attrName]
		if !ok {
			l.Warn("baton-ldap: attribute in update mask not found in attrs",
				zap.String("attr_name", attrName),
				zap.String("ldap_attr_name", ldapAttrName),
			)
			continue
		}

		if value == "" {
			// Empty value means delete the attribute.
			changes = append(changes, ldap3.Change{
				Operation: ldap3.DeleteAttribute,
				Modification: ldap3.PartialAttribute{
					Type: ldapAttrName,
				},
			})
		} else {
			changes = append(changes, ldap3.Change{
				Operation: ldap3.ReplaceAttribute,
				Modification: ldap3.PartialAttribute{
					Type: ldapAttrName,
					Vals: []string{value},
				},
			})
		}

		l.Info("baton-ldap: queuing attribute update",
			zap.String("profile_attr", attrName),
			zap.String("ldap_attr", ldapAttrName),
		)
	}

	return changes
}

func successResponse() *structpb.Struct {
	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"success": structpb.NewBoolValue(true),
		},
	}
}

// Ensure LDAP implements GlobalActionProvider at compile time.
var _ interface {
	GlobalActions(ctx context.Context, registry actions.ActionRegistry) error
} = (*LDAP)(nil)

