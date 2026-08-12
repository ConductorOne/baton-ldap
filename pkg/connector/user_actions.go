package connector

import (
	"context"
	"fmt"
	"sort"
	"strings"

	config_sdk "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	actionNameUpdateProfile = "update_profile"

	argUserID           = "user_id"
	argFirstName        = "first_name"
	argLastName         = "last_name"
	argDisplayName      = "display_name"
	argEmail            = "email"
	argCustomAttributes = "custom_attributes"
)

// profileNamedArgs are update_profile's named string fields, in schema and
// mask-precedence order. Order is load-bearing: it is the deterministic mask
// order fed to buildUserAttrChanges, which in turn drives its "first surviving
// entry wins" dedupe rule. Each name doubles as its own mask entry, since all
// four are already keys in profileAttrAliases (first_name/last_name/
// display_name/email resolve to givenName/sn/displayName/mail respectively).
var profileNamedArgs = []string{argFirstName, argLastName, argDisplayName, argEmail}

var _ connectorbuilder.ResourceActionProvider = (*userResourceType)(nil)

// updateProfileActionSchema returns the update_profile action schema. This
// must be a function that builds a fresh struct on every call, not a
// package-level var: actions.(*ActionManager).RegisterResourceAction mutates
// the schema in place (SetResourceTypeId) when it registers it, so a shared
// value would leak that mutation across every other holder of the same
// pointer (including, notably, a second call to this function racing a test).
//
// ResourceTypeId is intentionally left unset in the literal below --
// RegisterResourceAction stamps it from the resource syncer's own type
// ("user") at registration time; setting it here would be redundant at best
// and could be silently overwritten at worst.
func updateProfileActionSchema() *v2.BatonActionSchema {
	return &v2.BatonActionSchema{
		Name:        actionNameUpdateProfile,
		DisplayName: "Update User Profile",
		Description: "Set core profile fields (first name, last name, display name, email) and/or arbitrary custom LDAP " +
			"attributes on an existing user. A named field is applied only when it is present and non-empty (it cannot be " +
			"used to clear an attribute); use custom_attributes with an empty value to clear an attribute. A custom_attributes " +
			"key that collides with a named field above is dropped and reported in skipped, never merged with it. Password, " +
			"objectClass, and RDN attributes cannot be modified through this action.",
		ActionType: []v2.ActionType{
			v2.ActionType_ACTION_TYPE_ACCOUNT,
			v2.ActionType_ACTION_TYPE_ACCOUNT_UPDATE_PROFILE,
		},
		Arguments: []*config_sdk.Field{
			{
				Name:        argUserID,
				DisplayName: "User",
				Description: "The user to update.",
				IsRequired:  true,
				Field: &config_sdk.Field_ResourceIdField{
					ResourceIdField: &config_sdk.ResourceIdField{
						Rules: &config_sdk.ResourceIDRules{
							AllowedResourceTypeIds: []string{resourceTypeUser.Id},
						},
					},
				},
			},
			{
				Name:        argFirstName,
				DisplayName: "First Name",
				Description: "The user's first (given) name. Ignored if empty.",
				Field:       &config_sdk.Field_StringField{StringField: &config_sdk.StringField{}},
			},
			{
				Name:        argLastName,
				DisplayName: "Last Name",
				Description: "The user's last (surname) name. Ignored if empty.",
				Field:       &config_sdk.Field_StringField{StringField: &config_sdk.StringField{}},
			},
			{
				Name:        argDisplayName,
				DisplayName: "Display Name",
				Description: "The user's display name. Ignored if empty.",
				Field:       &config_sdk.Field_StringField{StringField: &config_sdk.StringField{}},
			},
			{
				Name:        argEmail,
				DisplayName: "Email",
				Description: "The user's email address. Ignored if empty.",
				Field:       &config_sdk.Field_StringField{StringField: &config_sdk.StringField{}},
			},
			{
				Name:        argCustomAttributes,
				DisplayName: "Custom Attributes",
				Description: "Map of arbitrary raw LDAP attribute name to value, for attributes beyond the named fields " +
					"above. An empty value clears the attribute.",
				Field: &config_sdk.Field_StringMapField{StringMapField: &config_sdk.StringMapField{}},
			},
		},
		ReturnTypes: []*config_sdk.Field{
			{
				Name:        "success",
				DisplayName: "Success",
				Field:       &config_sdk.Field_BoolField{BoolField: &config_sdk.BoolField{}},
			},
			{
				Name:        "updated_user",
				DisplayName: "Updated User",
				Description: "The user resource after the update, best-effort re-fetched. Absent if the read-back failed " +
					"(the write itself still succeeded in that case).",
				Field: &config_sdk.Field_ResourceField{ResourceField: &config_sdk.ResourceField{}},
			},
			{
				Name:        "applied",
				DisplayName: "Applied",
				Description: "The number of attributes modified.",
				Field:       &config_sdk.Field_IntField{IntField: &config_sdk.IntField{}},
			},
			{
				Name:        "skipped",
				DisplayName: "Skipped",
				Description: "Named fields or custom_attributes entries that were not written: an empty named field, a " +
					"custom_attributes key colliding with a named field, no value supplied, a synthetic key, or an RDN attribute.",
				Field: &config_sdk.Field_StringSliceField{StringSliceField: &config_sdk.StringSliceField{}},
			},
		},
	}
}

// ResourceActions registers update_profile as a resource-scoped action for
// the user resource type. The SDK detects this via type assertion against the
// same userBuilder(...) value already returned from LDAP.ResourceSyncers, so
// no connector.go changes are required.
func (u *userResourceType) ResourceActions(ctx context.Context, registry actions.ActionRegistry) error {
	if err := registry.Register(ctx, updateProfileActionSchema(), u.updateProfile); err != nil {
		return fmt.Errorf("ldap-connector: failed to register update_profile action: %w", err)
	}
	return nil
}

// buildProfileUpdate turns update_profile's arguments into the attrs/mask pair
// applyUserAttrUpdate/buildUserAttrChanges expect, plus a skipped list for
// entries that never make it into the mask at all (so they aren't silently
// dropped with no trace in the response -- R4). It is a pure function: no I/O,
// no logging, deterministic for a given args value.
//
// Mask order is: the four named fields in declared order (first_name,
// last_name, display_name, email), then custom_attributes keys sorted
// ascending. This is required for deterministic precedence in
// buildUserAttrChanges' dedupe (which keeps the first mask entry that resolves
// to a given attribute) and to make Go's randomized map iteration order a
// non-issue for repeated calls with the same input.
//
// Named-field semantics: a named field is included in the mask only when
// present AND non-empty (it cannot be used to clear an attribute); present-but-
// empty is reported in skipped rather than silently vanishing (R4). This
// mirrors buildUserAttrChanges' own "empty value clears" rule for
// custom_attributes, which is included whenever the key is present, regardless
// of value (empty clears, consistent with the global update_user_attrs action).
//
// Collision rule (R3): a custom_attributes key that case-insensitively matches
// one of the four named-argument names is dropped before it ever reaches the
// attrs/mask pair (never merged with, or silently overwriting, the named
// field's slot) and is reported once in skipped. This applies to the key
// itself, regardless of whether the corresponding named argument was actually
// supplied -- the reserved name is what's protected, not just an active value
// collision. Without this, a custom_attributes key with the exact same string
// as a named argument would collide as a map key in the returned attrs map
// (last write wins), silently clobbering one value with the other.
func buildProfileUpdate(args *structpb.Struct) (map[string]string, []string, []string, error) {
	attrs := map[string]string{}
	var mask []string
	var skipped []string

	namedLower := make(map[string]bool, len(profileNamedArgs))
	for _, name := range profileNamedArgs {
		namedLower[strings.ToLower(name)] = true
	}

	for _, name := range profileNamedArgs {
		value, present := args.GetFields()[name]
		if !present {
			// Absent is distinct from present-but-empty: nothing to report.
			continue
		}
		strVal, ok := value.GetKind().(*structpb.Value_StringValue)
		if !ok {
			return nil, nil, nil, fmt.Errorf("argument %q must be a string value", name)
		}
		if strVal.StringValue == "" {
			// R4: present-but-empty is dropped from the mask (named fields
			// cannot clear an attribute) but must be observable in the
			// response, not silently vanish.
			skipped = append(skipped, name)
			continue
		}
		attrs[name] = strVal.StringValue
		mask = append(mask, name)
	}

	custStruct, err := requireOptionalStructArg(args, argCustomAttributes)
	if err != nil {
		return nil, nil, nil, err
	}
	custom := map[string]string{}
	if custStruct != nil {
		for k, v := range custStruct.Fields {
			strVal, ok := v.GetKind().(*structpb.Value_StringValue)
			if !ok {
				return nil, nil, nil, fmt.Errorf("custom_attributes entry %q must be a string value", k)
			}
			custom[k] = strVal.StringValue
		}
	}

	customKeys := make([]string, 0, len(custom))
	for k := range custom {
		customKeys = append(customKeys, k)
	}
	sort.Strings(customKeys)

	for _, k := range customKeys {
		if namedLower[strings.ToLower(k)] {
			// R3: drop, don't merge/overwrite; report once.
			skipped = append(skipped, k)
			continue
		}
		attrs[k] = custom[k]
		mask = append(mask, k)
	}

	return attrs, mask, skipped, nil
}

// updateProfile is the update_profile resource-scoped action handler. Unlike
// updateUserAttrs, it has no empty-mask/empty-attrs early return: it always
// runs the full applyUserAttrUpdate pipeline, so a vanished or out-of-scope
// user still surfaces as NotFound even if every field the caller sent was
// empty or absent.
func (u *userResourceType) updateProfile(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	log := ctxzap.Extract(ctx)

	userRef, ok := actions.GetResourceIDArg(args, argUserID)
	if !ok || userRef.GetResource() == "" {
		return nil, nil, status.Errorf(codes.InvalidArgument, "ldap-connector: %s: user_id is required", actionNameUpdateProfile)
	}
	if rt := userRef.GetResourceType(); rt != "" && rt != resourceTypeUser.Id {
		return nil, nil, status.Errorf(codes.InvalidArgument, "ldap-connector: %s: user_id must reference a %q resource, got %q",
			actionNameUpdateProfile, resourceTypeUser.Id, rt)
	}

	attrs, mask, skipped, err := buildProfileUpdate(args)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "ldap-connector: %s: %v", actionNameUpdateProfile, err)
	}

	result, err := applyUserAttrUpdate(ctx, u.client, u.userSearchDN, actionNameUpdateProfile, userRef.GetResource(), attrs, mask)
	if err != nil {
		return nil, nil, err
	}

	skipped = append(skipped, result.Skipped...)

	fields := []actions.ReturnField{
		actions.NewNumberReturnField("applied", float64(result.Applied)),
		actions.NewStringListReturnField("skipped", skipped),
	}

	// Best-effort read-back: never fails the whole action. The write already
	// landed by this point, so a read-back or resource-encoding problem should
	// not turn a successful modify into a reported failure.
	if entry, rerr := getAccount(ctx, u.client, result.DN); rerr != nil {
		log.Warn("update_profile: read-back failed", zap.String("dn", result.DN), zap.Error(rerr))
	} else if updatedRes, rerr := userResource(ctx, entry); rerr != nil {
		log.Warn("update_profile: encoding updated user resource failed", zap.String("dn", result.DN), zap.Error(rerr))
	} else if rf, ferr := actions.NewResourceReturnField("updated_user", updatedRes); ferr != nil {
		log.Warn("update_profile: encoding updated_user return field failed", zap.String("dn", result.DN), zap.Error(ferr))
	} else {
		fields = append(fields, rf)
	}

	return actions.NewReturnValues(true, fields...), nil, nil
}
