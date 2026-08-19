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

// profileNamedField binds one of update_profile's named string arguments to the
// real LDAP attribute it writes.
type profileNamedField struct {
	// arg is the public argument name, as it appears in the action schema and
	// in the skipped list returned to the caller.
	arg string
	// attr is the real LDAP attribute the argument writes.
	attr string
}

// profileNamedFields are update_profile's named string fields, in schema and
// mask-precedence order. Order is load-bearing: it is the deterministic mask
// order fed to buildUserAttrChanges, which in turn drives its "first surviving
// entry wins" dedupe rule.
//
// This table is the ONLY place a public field name is translated into an LDAP
// attribute name. It deliberately does not cover custom_attributes: those keys
// are documented as raw LDAP attribute names and are passed through verbatim,
// so a caller who writes "user_id" gets an attribute literally named user_id
// (and a loud server-side undefinedAttributeType rejection if their directory
// has no such attribute) rather than a silent redirect to uid.
//
// The alias is functionally required for the named fields, not cosmetic:
// first_name/last_name can carry values derived from splitting cn when
// givenName/sn are absent, so writing them back only means anything once
// they're resolved to the real attribute; display_name/email alias for naming
// consistency with the rest of the public API.
var profileNamedFields = []profileNamedField{
	{arg: argFirstName, attr: attrFirstName},         // givenName
	{arg: argLastName, attr: attrLastName},           // sn
	{arg: argDisplayName, attr: attrUserDisplayName}, // displayName
	{arg: argEmail, attr: attrUserMail},              // mail
}

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
			"used to clear an attribute); use custom_attributes with an empty value to clear an attribute. Named fields map to " +
			"real LDAP attributes (first_name -> givenName, last_name -> sn, display_name -> displayName, email -> mail); " +
			"custom_attributes keys are used verbatim as LDAP attribute names and are never remapped. A custom_attributes " +
			"key that collides with a named field above, or with the attribute one of them is writing, is dropped and " +
			"reported in skipped, never merged with it. Password, objectClass, and RDN attributes cannot be modified " +
			"through this action.",
		ActionType: []v2.ActionType{
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
					"above. Each key is used verbatim as the LDAP attribute name -- unlike the named fields, it is never " +
					"translated to a different attribute. An empty value clears the attribute.",
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
					"custom_attributes key colliding with a named field or with the attribute one is writing, no value " +
					"supplied, or an RDN attribute.",
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
// Name resolution happens HERE and nowhere downstream. Named fields are
// translated to their real LDAP attribute through profileNamedFields
// (first_name -> givenName, and so on), so the mask this returns is entirely
// literal LDAP attribute names: a resolved named-field attribute, or a
// custom_attributes key passed through verbatim. buildUserAttrChanges then
// writes exactly what it is given. custom_attributes is documented as taking
// raw LDAP attribute names, and this is what makes that true -- previously
// every key ran through the same alias table as the named fields, so
// custom_attributes["user_id"] silently wrote uid instead.
//
// Mask order is: the named fields' attributes in declared order (givenName, sn,
// displayName, mail), then custom_attributes keys sorted ascending. This is
// required for deterministic precedence in buildUserAttrChanges' dedupe (which
// keeps the first mask entry naming a given attribute) and to make Go's
// randomized map iteration order a non-issue for repeated calls with the same
// input.
//
// Named-field semantics: a named field is included in the mask only when
// present AND non-empty (it cannot be used to clear an attribute); present-but-
// empty is reported in skipped rather than silently vanishing (R4). This
// mirrors buildUserAttrChanges' own "empty value clears" rule for
// custom_attributes, which is included whenever the key is present, regardless
// of value. Note that skipped reports the ARGUMENT name (first_name) rather
// than the attribute (givenName), since that is the name the caller supplied.
//
// Collision rules (R3): a custom_attributes key is dropped before it ever
// reaches the attrs/mask pair -- never merged with, or silently overwriting, a
// named field's slot -- and reported once in skipped when it case-insensitively
// matches either
//
//   - one of the four named-argument names (first_name, last_name,
//     display_name, email). This applies regardless of whether the
//     corresponding named argument was actually supplied: the reserved name is
//     what's protected, not just an active value collision.
//   - the real LDAP attribute of a named field that DID claim a mask slot
//     (givenName, sn, displayName, mail). Only an actually-claimed slot
//     collides, so custom_attributes["givenName"] remains a perfectly valid raw
//     write whenever first_name is absent or present-but-empty.
//
// Without these, a colliding custom_attributes key would land on the same map
// key in the returned attrs (last write wins), silently clobbering one value
// with the other.
func buildProfileUpdate(args *structpb.Struct) (map[string]string, []string, []string, error) {
	attrs := map[string]string{}
	var mask []string
	var skipped []string

	// Reserved names a custom_attributes key may not use: the named-argument
	// names always, plus the real attribute of any named field that actually
	// claimed a mask slot below.
	reserved := make(map[string]bool, len(profileNamedFields)*2)
	for _, f := range profileNamedFields {
		reserved[strings.ToLower(f.arg)] = true
	}

	for _, f := range profileNamedFields {
		value, present := args.GetFields()[f.arg]
		if !present {
			// Absent is distinct from present-but-empty: nothing to report.
			continue
		}
		strVal, ok := value.GetKind().(*structpb.Value_StringValue)
		if !ok {
			return nil, nil, nil, fmt.Errorf("argument %q must be a string value", f.arg)
		}
		if strVal.StringValue == "" {
			// R4: present-but-empty is dropped from the mask (named fields
			// cannot clear an attribute) but must be observable in the
			// response, not silently vanish.
			skipped = append(skipped, f.arg)
			continue
		}
		attrs[f.attr] = strVal.StringValue
		mask = append(mask, f.attr)
		reserved[strings.ToLower(f.attr)] = true
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
		if reserved[strings.ToLower(k)] {
			// R3: drop, don't merge/overwrite; report once.
			skipped = append(skipped, k)
			continue
		}
		// Verbatim: a custom_attributes key IS the LDAP attribute name.
		attrs[k] = custom[k]
		mask = append(mask, k)
	}

	return attrs, mask, skipped, nil
}

// updateProfile is the update_profile resource-scoped action handler. It has
// no empty-mask/empty-attrs early return: it always runs the full
// applyUserAttrUpdate pipeline, so a vanished or out-of-scope user still
// surfaces as NotFound even if every field the caller sent was empty or
// absent.
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
