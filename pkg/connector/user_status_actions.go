package connector

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/conductorone/baton-ldap/pkg/ldap"
	config_sdk "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	actionNameEnableUser  = "enable_user"
	actionNameDisableUser = "disable_user"

	statusNameEnabled  = "enabled"
	statusNameDisabled = "disabled"
)

// userStatusActionSchema builds the schema for one of the enable/disable
// actions. Like updateProfileActionSchema this must return a fresh struct on
// every call -- actions.(*ActionManager).Register mutates the schema in place
// on registration, so a shared package-level value would leak that mutation to
// every other holder of the same pointer.
func userStatusActionSchema(name, displayName, description string, actionType v2.ActionType) *v2.BatonActionSchema {
	return &v2.BatonActionSchema{
		Name:        name,
		DisplayName: displayName,
		Description: description,
		ActionType:  []v2.ActionType{actionType},
		Arguments: []*config_sdk.Field{
			{
				Name:        argUserID,
				DisplayName: "User",
				Description: "The user to enable or disable.",
				IsRequired:  true,
				Field: &config_sdk.Field_ResourceIdField{
					ResourceIdField: &config_sdk.ResourceIdField{
						Rules: &config_sdk.ResourceIDRules{
							AllowedResourceTypeIds: []string{resourceTypeUser.Id},
						},
					},
				},
			},
		},
		ReturnTypes: []*config_sdk.Field{
			{
				Name:        "success",
				DisplayName: "Success",
				Field:       &config_sdk.Field_BoolField{BoolField: &config_sdk.BoolField{}},
			},
			{
				Name:        "status",
				DisplayName: "Status",
				Description: "The lifecycle status the action applied: \"enabled\" or \"disabled\".",
				Field:       &config_sdk.Field_StringField{StringField: &config_sdk.StringField{}},
			},
			{
				Name:        "applied",
				DisplayName: "Applied",
				Description: "The number of attributes modified. Zero means the account was already in the requested state.",
				Field:       &config_sdk.Field_IntField{IntField: &config_sdk.IntField{}},
			},
			{
				Name:        "skipped",
				DisplayName: "Skipped",
				Description: "Configured attributes this action could not write. Non-empty is an error condition, never a partial success.",
				Field:       &config_sdk.Field_StringSliceField{StringSliceField: &config_sdk.StringSliceField{}},
			},
			{
				Name:        "updated_user",
				DisplayName: "Updated User",
				Description: "The user resource after the change, best-effort re-fetched. Absent if the read-back failed (the write itself still succeeded in that case).",
				Field:       &config_sdk.Field_ResourceField{ResourceField: &config_sdk.ResourceField{}},
			},
		},
	}
}

func enableUserActionSchema() *v2.BatonActionSchema {
	return userStatusActionSchema(
		actionNameEnableUser,
		"Enable User",
		"Mark a user account as enabled by writing the attributes configured in enable-user-attributes. Only the attributes "+
			"named in that configuration are written; attributes that only disable-user-attributes names are left untouched.",
		v2.ActionType_ACTION_TYPE_ACCOUNT_ENABLE,
	)
}

func disableUserActionSchema() *v2.BatonActionSchema {
	return userStatusActionSchema(
		actionNameDisableUser,
		"Disable User",
		"Mark a user account as disabled by writing the attributes configured in disable-user-attributes. Only the attributes "+
			"named in that configuration are written; attributes that only enable-user-attributes names are left untouched.",
		v2.ActionType_ACTION_TYPE_ACCOUNT_DISABLE,
	)
}

// buildUserStatusAttrs turns one direction's configured attribute map into the
// attrs/mask pair applyUserAttrUpdate expects. It is a pure function: it copies
// the map, so a caller cannot reach back into the connector's configuration
// through the returned value, and performs no I/O.
//
// The mask is sorted ascending because buildUserAttrChanges keeps the FIRST
// mask entry naming an attribute and Go's map iteration order is randomized;
// without the sort, two keys folding to the same attribute would resolve
// non-deterministically (buildProfileUpdate sorts its custom keys for the same
// reason).
func buildUserStatusAttrs(configured map[string]string) (map[string]string, []string) {
	attrs := make(map[string]string, len(configured))
	mask := make([]string, 0, len(configured))
	for name, value := range configured {
		attrs[name] = value
		mask = append(mask, name)
	}
	sort.Strings(mask)
	return attrs, mask
}

// statusAttributeConfigField names the connector configuration key that drives
// one direction of the enable/disable definition, for error messages.
func statusAttributeConfigField(disable bool) string {
	if disable {
		return "disable-user-attributes"
	}
	return "enable-user-attributes"
}

// disableUser marks the user disabled by writing disable-user-attributes.
func (l *LDAP) disableUser(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	return l.setUserEnabled(ctx, args, true)
}

// enableUser marks the user enabled by writing enable-user-attributes.
func (l *LDAP) enableUser(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	return l.setUserEnabled(ctx, args, false)
}

// setUserEnabled is the shared handler behind enable_user and disable_user.
//
// Direction isolation is structural: only the invoked direction's configured
// map reaches the write, so the other direction's attributes are left
// untouched rather than implicitly cleared. The read path's union of both maps
// and this isolation agree only because the configuration requires both
// directions to name the same attributes whenever both are configured.
func (l *LDAP) setUserEnabled(ctx context.Context, args *structpb.Struct, disable bool) (*structpb.Struct, annotations.Annotations, error) {
	log := ctxzap.Extract(ctx)

	actionName := actionNameEnableUser
	configured := l.config.UserStatusAttributes.Enabled
	statusName := statusNameEnabled
	if disable {
		actionName = actionNameDisableUser
		configured = l.config.UserStatusAttributes.Disabled
		statusName = statusNameDisabled
	}

	userRef, ok := actions.GetResourceIDArg(args, argUserID)
	if !ok || userRef.GetResource() == "" {
		return nil, nil, status.Errorf(codes.InvalidArgument, "ldap-connector: %s: user_id is required", actionName)
	}
	if rt := userRef.GetResourceType(); rt != "" && rt != resourceTypeUser.Id {
		return nil, nil, status.Errorf(codes.InvalidArgument, "ldap-connector: %s: user_id must reference a %q resource, got %q",
			actionName, resourceTypeUser.Id, rt)
	}

	attrs, mask := buildUserStatusAttrs(configured)

	// Defensive: an empty direction would otherwise "succeed" without writing
	// anything. Registration already withholds the action in that case, so this
	// only fires for a caller reaching the handler some other way.
	if len(mask) == 0 {
		return nil, nil, status.Errorf(codes.FailedPrecondition,
			"ldap-connector: %s: no attributes are configured for this direction; set the connector's %s configuration",
			actionName, statusAttributeConfigField(disable))
	}

	result, err := applyUserAttrUpdate(ctx, l.client, l.config.UserSearchDN, actionName, userRef.GetResource(), attrs, mask)
	if err != nil {
		return nil, nil, err
	}

	// A skip means the configuration names an attribute this action cannot
	// write (the entry's RDN attribute, or a mask entry folded onto another).
	// Whether a change was emitted is irrelevant: Skipped is a property of the
	// configuration and the entry, never of the already-satisfied paths, so it
	// must fail on the first call exactly as it fails on every retry.
	// Conditioning it on Applied would let the action succeed once and then
	// fail forever -- precisely the wrong shape for an action C1 retries.
	if len(result.Skipped) > 0 {
		log.Warn(actionName+": configured attributes could not be written",
			zap.String("dn", result.DN), zap.Strings("skipped", result.Skipped))
		return nil, nil, status.Errorf(codes.FailedPrecondition,
			"ldap-connector: %s: attribute(s) %s cannot be written by this action; remove them from the connector's configuration",
			actionName, strings.Join(result.Skipped, ", "))
	}

	// Verify what was actually written rather than recomputing the status enum:
	// a configured clear leaves the attribute absent, so the enum would fall
	// through to UNSPECIFIED and fail a perfectly correct write.
	if err := verifyUserStatusAttrs(ctx, l.client, result.DN, attrs, mask, actionName); err != nil {
		return nil, nil, err
	}

	fields := []actions.ReturnField{
		actions.NewStringReturnField("status", statusName),
		actions.NewNumberReturnField("applied", float64(result.Applied)),
		actions.NewStringListReturnField("skipped", result.Skipped),
	}

	// Best-effort read-back: the write already landed, so a read-back or
	// resource-encoding problem must not turn a successful modify into a
	// reported failure.
	if entry, rerr := getAccount(ctx, l.client, result.DN); rerr != nil {
		log.Warn(actionName+": read-back failed", zap.String("dn", result.DN), zap.Error(rerr))
	} else if updatedRes, rerr := userResource(ctx, entry, l.config.UserStatusAttributes); rerr != nil {
		log.Warn(actionName+": encoding updated user resource failed", zap.String("dn", result.DN), zap.Error(rerr))
	} else if rf, ferr := actions.NewResourceReturnField("updated_user", updatedRes); ferr != nil {
		log.Warn(actionName+": encoding updated_user return field failed", zap.String("dn", result.DN), zap.Error(ferr))
	} else {
		fields = append(fields, rf)
	}

	return actions.NewReturnValues(true, fields...), nil, nil
}

// verifyUserStatusAttrs re-reads the entry and asserts every attribute this
// action targeted holds its configured value, or is absent when the configured
// value is empty (an explicit clear). A mismatch is FailedPrecondition: the
// write reported success but the directory does not reflect it, and retrying
// the identical action will not change that.
func verifyUserStatusAttrs(ctx context.Context, client *ldap.Client, dn string, attrs map[string]string, mask []string, actionName string) error {
	entry, err := getAccount(ctx, client, dn)
	if err != nil {
		return status.Errorf(lookupErrToGRPC(err), "ldap-connector: %s: failed to verify user %q: %v", actionName, dn, err)
	}
	if err := assertStatusAttrsWritten(entry, attrs, mask); err != nil {
		return status.Errorf(codes.FailedPrecondition, "ldap-connector: %s: %v", actionName, err)
	}
	return nil
}

// assertStatusAttrsWritten is the pure half of the read-back verification: it
// asserts each mask entry's configured value is present on the entry
// (case-insensitive, whitespace-trimmed, any-value match) or absent when the
// configured value is empty. Error messages name the attribute and the number
// of values found, never the values themselves.
func assertStatusAttrsWritten(entry *ldap.Entry, attrs map[string]string, mask []string) error {
	for _, attr := range mask {
		expected, ok := attrs[attr]
		if !ok {
			return fmt.Errorf("attribute %q is not part of the configured attribute set", attr)
		}
		current := entry.GetEqualFoldAttributeValues(attr)
		if expected == "" {
			if len(current) > 0 {
				return fmt.Errorf("attribute %q still holds %d value(s) after this action cleared it", attr, len(current))
			}
			continue
		}
		if !anyAttrValueMatches(current, expected) {
			return fmt.Errorf("attribute %q does not hold its configured value after this action ran (%d value(s) present)", attr, len(current))
		}
	}
	return nil
}

// attrValueMatches reports whether an LDAP attribute value matches a configured
// value. Both sides are whitespace-trimmed and compared case-insensitively,
// which is the same comparison the read path uses.
func attrValueMatches(value, configured string) bool {
	return strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(configured))
}

// anyAttrValueMatches reports whether any of the entry's values for an
// attribute matches the configured value.
func anyAttrValueMatches(values []string, configured string) bool {
	for _, value := range values {
		if attrValueMatches(value, configured) {
			return true
		}
	}
	return false
}
