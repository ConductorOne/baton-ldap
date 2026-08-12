package connector

import (
	"context"
	"fmt"
	"strings"

	"github.com/conductorone/baton-ldap/pkg/ldap"
	config_sdk "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	ldapObjectClassOU   = "organizationalUnit"
	ldapAttrOU          = "ou"
	ldapAttrDescription = "description"
	actionNameCreateOU  = "create_ou"
	argName             = "name"
	argParentDN         = "parent_dn"
	argDescription      = "description"

	actionNameUpdateUserAttrs = "update_user_attrs"
	argResourceID             = "resource_id"
	argAttrs                  = "attrs"
	argAttrsUpdateMask        = "attrs_update_mask"
	ldapAttrObjectClass       = "objectClass"
)

// profileAttrAliases maps baton-ldap's synthetic user-profile keys (produced by
// userResource) to the real LDAP attribute they represent. A mask name not in
// this map (and not in profileSyntheticSkip) is treated as a raw LDAP attribute
// name. Keys are compared case-insensitively.
//
// Note: adding "email" here changes the existing global update_user_attrs
// action's behavior for a mask entry named "email": previously it tried to
// write a nonexistent raw "email" attribute (a no-op/failure depending on
// directory schema); now it correctly maps to "mail". Strict improvement, but
// a behavior change on a shipped path.
var profileAttrAliases = map[string]string{
	"first_name":   attrFirstName,       // givenName
	"last_name":    attrLastName,        // sn
	"display_name": attrUserDisplayName, // displayName
	"user_id":      attrUserUID,         // uid
	"email":        attrUserMail,        // mail
}

// profileSyntheticSkip are synthetic profile keys with no single LDAP attribute
// to write. If present in the update mask they are skipped (reported, not written).
var profileSyntheticSkip = map[string]bool{
	"login":         true,
	schemaFieldPath: true, // "path"
}

var _ connectorbuilder.GlobalActionProvider = (*LDAP)(nil)

// buildOUDN validates the OU name and parent, enforces the fail-closed base-dn
// scope check, and returns the fully-qualified DN for the new OU
// (ou=<escaped-name>,<canonical-parent>). Returned errors are lowercase
// fragments; callers add the connector prefix.
func buildOUDN(name, parentDN string, baseDN *ldap3.DN) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if baseDN == nil {
		return "", fmt.Errorf("base-dn must be configured")
	}
	// Don't assume the stored BaseDN is canonical (the test harness builds it via
	// raw ParseDN); canonicalize so the comparison and the rejection message use
	// normalized values.
	rawBaseDN := baseDN.String()
	baseDN, err := ldap.CanonicalizeDN(rawBaseDN)
	if err != nil {
		return "", fmt.Errorf("invalid base-dn %q: %w", rawBaseDN, err)
	}

	parentDN = strings.TrimSpace(parentDN)
	parent := baseDN
	if parentDN != "" {
		parent, err = ldap.CanonicalizeDN(parentDN)
		if err != nil {
			return "", fmt.Errorf("invalid parent_dn %q: %w", parentDN, err)
		}
	}

	if !baseDN.EqualFold(parent) && !baseDN.AncestorOfFold(parent) {
		return "", fmt.Errorf("parent_dn %q is outside the configured base-dn %q", parent.String(), baseDN.String())
	}

	return fmt.Sprintf("%s=%s,%s", ldapAttrOU, ldap3.EscapeDN(name), parent.String()), nil
}

func createOUActionSchema() *v2.BatonActionSchema {
	return &v2.BatonActionSchema{
		Name:        actionNameCreateOU,
		DisplayName: "Create Organizational Unit",
		Description: "Create an LDAP organizational unit (OU) under a parent container within the configured base DN.",
		ActionType:  []v2.ActionType{v2.ActionType_ACTION_TYPE_RESOURCE_CREATE},
		Arguments: []*config_sdk.Field{
			{
				Name:        argName,
				DisplayName: "Name",
				Description: "The OU name (used as the ou attribute and RDN).",
				IsRequired:  true,
				Field:       &config_sdk.Field_StringField{StringField: &config_sdk.StringField{}},
			},
			{
				Name:        argParentDN,
				DisplayName: "Parent DN",
				Description: "The container DN under which to create the OU. Defaults to the configured base DN if empty.",
				Field:       &config_sdk.Field_StringField{StringField: &config_sdk.StringField{}},
			},
			{
				Name:        argDescription,
				DisplayName: "Description",
				Description: "Optional description attribute for the OU.",
				Field:       &config_sdk.Field_StringField{StringField: &config_sdk.StringField{}},
			},
		},
		ReturnTypes: []*config_sdk.Field{
			{
				Name:        "ou_dn",
				DisplayName: "OU DN",
				Description: "The distinguished name of the created OU.",
				Field:       &config_sdk.Field_StringField{StringField: &config_sdk.StringField{}},
			},
			{
				Name:        "success",
				DisplayName: "Success",
				Field:       &config_sdk.Field_BoolField{BoolField: &config_sdk.BoolField{}},
			},
		},
	}
}

func updateUserAttrsActionSchema() *v2.BatonActionSchema {
	return &v2.BatonActionSchema{
		Name:        actionNameUpdateUserAttrs,
		DisplayName: "Update User Attributes",
		Description: "Set or clear arbitrary LDAP attributes on an existing user. An empty value clears the attribute. " +
			"Password, objectClass, and RDN attributes cannot be modified through this action.",
		ActionType: []v2.ActionType{
			v2.ActionType_ACTION_TYPE_ACCOUNT,
			v2.ActionType_ACTION_TYPE_ACCOUNT_UPDATE_PROFILE,
		},
		Arguments: []*config_sdk.Field{
			{
				Name:        argResourceID,
				DisplayName: "Resource ID",
				Description: "The distinguished name (DN) of the user to update.",
				IsRequired:  true,
				Field:       &config_sdk.Field_StringField{StringField: &config_sdk.StringField{}},
			},
			{
				Name:        argAttrs,
				DisplayName: "Attributes",
				Description: "Map of LDAP attribute name to value. An empty value clears the attribute.",
				IsRequired:  true,
				Field:       &config_sdk.Field_StringMapField{StringMapField: &config_sdk.StringMapField{}},
			},
			{
				Name:        argAttrsUpdateMask,
				DisplayName: "Attributes Update Mask",
				Description: "The subset of attribute names from \"attrs\" to actually write.",
				IsRequired:  true,
				Field:       &config_sdk.Field_StringSliceField{StringSliceField: &config_sdk.StringSliceField{}},
			},
		},
		ReturnTypes: []*config_sdk.Field{
			{
				Name:        "success",
				DisplayName: "Success",
				Field:       &config_sdk.Field_BoolField{BoolField: &config_sdk.BoolField{}},
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
				Description: "Mask entries that were not written (no value supplied, synthetic key, or RDN attribute).",
				Field:       &config_sdk.Field_StringSliceField{StringSliceField: &config_sdk.StringSliceField{}},
			},
		},
	}
}

// requireOptionalStructArg extracts the struct-typed value at key. It returns
// (nil, nil) when the key is absent, and an error when the key is present but
// not a struct (rather than silently discarding the type mismatch and treating
// it as absent -- the bug in actions.GetStructArg's boolean "ok" being blind to
// this distinction).
func requireOptionalStructArg(args *structpb.Struct, key string) (*structpb.Struct, error) {
	value, present := args.GetFields()[key]
	if !present {
		return nil, nil
	}
	structValue, ok := value.GetKind().(*structpb.Value_StructValue)
	if !ok {
		return nil, fmt.Errorf("%s must be a struct", key)
	}
	return structValue.StructValue, nil
}

// requireOptionalStringSliceArg extracts the string-list value at key. It
// returns (nil, nil) when the key is absent, and an error when the key is
// present but not a list of strings (see requireOptionalStructArg).
func requireOptionalStringSliceArg(args *structpb.Struct, key string) ([]string, error) {
	value, present := args.GetFields()[key]
	if !present {
		return nil, nil
	}
	listValue, ok := value.GetKind().(*structpb.Value_ListValue)
	if !ok {
		return nil, fmt.Errorf("%s must be a list of strings", key)
	}
	result := make([]string, 0, len(listValue.ListValue.Values))
	for _, v := range listValue.ListValue.Values {
		strVal, ok := v.GetKind().(*structpb.Value_StringValue)
		if !ok {
			return nil, fmt.Errorf("%s entries must be strings", key)
		}
		result = append(result, strVal.StringValue)
	}
	return result, nil
}

// GlobalActions registers the connector's global actions. The SDK detects this
// via type assertion in NewConnector and serves the registered actions.
func (l *LDAP) GlobalActions(ctx context.Context, registry actions.ActionRegistry) error {
	if err := registry.Register(ctx, createOUActionSchema(), l.createOU); err != nil {
		return fmt.Errorf("ldap-connector: failed to register create_ou action: %w", err)
	}
	if err := registry.Register(ctx, updateUserAttrsActionSchema(), l.updateUserAttrs); err != nil {
		return fmt.Errorf("ldap-connector: failed to register update_user_attrs action: %w", err)
	}
	return nil
}

// createOU creates an organizationalUnit entry and verifies it was written.
// The SDK does not enforce per-field IsRequired, so name is validated here.
func (l *LDAP) createOU(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	log := ctxzap.Extract(ctx)

	name, err := actions.RequireStringArg(args, argName)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "ldap-connector: create_ou: %v", err)
	}
	name = strings.TrimSpace(name)
	parentArg, _ := actions.GetStringArg(args, argParentDN)
	description, _ := actions.GetStringArg(args, argDescription)
	description = strings.TrimSpace(description)

	ouDN, err := buildOUDN(name, parentArg, l.config.BaseDN)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "ldap-connector: create_ou: %v", err)
	}

	log.Debug("creating organizational unit", zap.String("dn", ouDN))

	addReq := ldap3.NewAddRequest(ouDN, nil)
	addReq.Attribute("objectClass", []string{ldapObjectClassTop, ldapObjectClassOU})
	addReq.Attribute(ldapAttrOU, []string{name})
	if description != "" {
		addReq.Attribute(ldapAttrDescription, []string{description})
	}

	if err := l.client.LdapAdd(ctx, addReq); err != nil {
		log.Error("create_ou: add failed", zap.String("dn", ouDN), zap.Error(err))
		return nil, nil, fmt.Errorf("ldap-connector: create_ou: failed to add ou %q: %w", ouDN, err)
	}

	// Verify the entry exists. LdapAdd masks EntryAlreadyExists/UnwillingToPerform
	// to nil, so a nil error above does not prove the write landed. LdapGetRaw
	// bypasses the connector-wide filter and returns an error when the DN is
	// absent or not an organizationalUnit.
	if _, err := l.client.LdapGetRaw(ctx, ouDN, fmt.Sprintf("(objectClass=%s)", ldapObjectClassOU), []string{ldapAttrOU}); err != nil {
		log.Error("create_ou: verification failed", zap.String("dn", ouDN), zap.Error(err))
		return nil, nil, fmt.Errorf("ldap-connector: create_ou: ou %q was not created: %w", ouDN, err)
	}

	return actions.NewReturnValues(true, actions.NewStringReturnField("ou_dn", ouDN)), nil, nil
}

// updateUserAttrs sets or clears arbitrary LDAP attributes on an existing user.
// It backs the C1 profile-push pipeline (ACTION_TYPE_ACCOUNT_UPDATE_PROFILE) and
// is also invocable directly. Only the attribute names listed in the update mask
// are written; an empty value clears the attribute. See buildUserAttrChanges for
// the alias/denylist/idempotency rules.
func (l *LDAP) updateUserAttrs(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	resourceID, err := actions.RequireStringArg(args, argResourceID)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "ldap-connector: update_user_attrs: %v", err)
	}

	// attrs is a StringMap, delivered as a nested struct of string values.
	attrsStruct, err := requireOptionalStructArg(args, argAttrs)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "ldap-connector: update_user_attrs: %v", err)
	}
	attrs := map[string]string{}
	if attrsStruct != nil {
		for k, v := range attrsStruct.Fields {
			strVal, ok := v.GetKind().(*structpb.Value_StringValue)
			if !ok {
				return nil, nil, status.Errorf(codes.InvalidArgument, "ldap-connector: update_user_attrs: attribute %q value must be a string", k)
			}
			attrs[k] = strVal.StringValue
		}
	}

	mask, err := requireOptionalStringSliceArg(args, argAttrsUpdateMask)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "ldap-connector: update_user_attrs: %v", err)
	}

	// An empty mask is a no-op success (the push pipeline may send no fields).
	// This check must stay here, ahead of DN canonicalization/scope-check/fetch,
	// and must NOT move into applyUserAttrUpdate: today a malformed or
	// out-of-scope resource_id combined with an empty mask returns success
	// (never inspected), and that is the existing, tested behavior of this
	// handler. applyUserAttrUpdate deliberately has no such early return -- its
	// other caller (update_profile) needs the full pipeline to run even for an
	// empty mask, so a vanished/out-of-scope user still surfaces as NotFound
	// instead of a false success.
	if len(mask) == 0 {
		return updateUserAttrsResult(0, nil), nil, nil
	}

	// Fail-closed scope check target: only entries within the configured user
	// search scope may be modified.
	scopeDN := l.config.UserSearchDN
	if scopeDN == nil {
		scopeDN = l.config.BaseDN
	}

	result, err := applyUserAttrUpdate(ctx, l.client, scopeDN, actionNameUpdateUserAttrs, resourceID, attrs, mask)
	if err != nil {
		return nil, nil, err
	}

	return updateUserAttrsResult(result.Applied, result.Skipped), nil, nil
}

// userAttrUpdate is the result of a successful applyUserAttrUpdate call.
type userAttrUpdate struct {
	// DN is the canonical DN of the modified entry, as read back from the
	// fetched account (not necessarily identical in casing/spacing to the
	// caller-supplied resourceID).
	DN string
	// Applied is the number of attributes actually modified.
	Applied int
	// Skipped lists mask entries that were not written; see buildUserAttrChanges.
	Skipped []string
}

// applyUserAttrUpdate runs the full canonicalize -> fail-closed scope-check ->
// fetch -> diff -> modify pipeline shared by updateUserAttrs (the global
// action) and updateProfile (the resource-scoped action). It always runs this
// complete pipeline and has no empty-mask/empty-attrs early return of its own
// -- see the comment on the caller-side early return in updateUserAttrs for
// why that matters and must not move here.
//
// Status codes are deliberately identical regardless of caller: InvalidArgument
// for a malformed resourceID, NotFound for an out-of-scope or missing user
// (deliberately indistinguishable, to avoid leaking the existence of entries
// outside the connector's managed subtree), and a plain wrapped error
// (surfaced by the SDK as a FAILED action) for a real server modify rejection.
// actionName only varies message text, never the status code.
func applyUserAttrUpdate(
	ctx context.Context,
	client *ldap.Client,
	scopeDN *ldap3.DN,
	actionName string,
	resourceID string,
	attrs map[string]string,
	mask []string,
) (*userAttrUpdate, error) {
	log := ctxzap.Extract(ctx)

	targetDN, err := ldap.CanonicalizeDN(resourceID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "ldap-connector: %s: invalid resource_id %q: %v", actionName, resourceID, err)
	}

	// Fail-closed scope check: only entries within the configured user search
	// scope may be modified. Report out-of-scope as NotFound to avoid leaking
	// the existence of entries outside the connector's managed subtree.
	if err := assertDNInScope(targetDN, scopeDN); err != nil {
		log.Debug(actionName+": target out of scope", zap.String("dn", targetDN.String()), zap.Error(err))
		return nil, status.Errorf(codes.NotFound, "ldap-connector: %s: user not found", actionName)
	}

	// Fetch the entry: confirms it exists and is a user, and lets us pre-filter
	// no-op changes so re-runs are idempotent without relying on the client's
	// error masking.
	acc, err := getAccount(ctx, client, targetDN.String())
	if err != nil {
		log.Debug(actionName+": user lookup failed", zap.String("dn", targetDN.String()), zap.Error(err))
		return nil, status.Errorf(codes.NotFound, "ldap-connector: %s: user not found", actionName)
	}

	changes, skipped, err := buildUserAttrChanges(ctx, acc, targetDN, attrs, mask, actionName)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "ldap-connector: %s: %v", actionName, err)
	}

	if len(changes) == 0 {
		log.Info(actionName+": nothing to apply", zap.String("dn", acc.DN), zap.Strings("skipped", skipped))
		return &userAttrUpdate{DN: acc.DN, Applied: 0, Skipped: skipped}, nil
	}

	// Use the strict modify so genuine schema/permission rejections surface
	// (the default LdapModify would mask UnwillingToPerform et al. to nil).
	req := &ldap3.ModifyRequest{DN: acc.DN, Changes: changes}
	if err := client.LdapModifyStrict(ctx, req); err != nil {
		// Log attribute names and value lengths only; values may be PII.
		fields := []zap.Field{zap.Error(err), zap.String("dn", acc.DN)}
		for _, ch := range changes {
			if len(ch.Modification.Vals) == 0 {
				fields = append(fields, zap.String("attr:"+ch.Modification.Type, "clear"))
			} else {
				fields = append(fields, zap.String("attr:"+ch.Modification.Type, fmt.Sprintf("len=%d", len(ch.Modification.Vals[0]))))
			}
		}
		// Warn, not Error: most modify rejections here (permission denied, schema
		// violations) are expected customer-config conditions, not connector bugs,
		// so they shouldn't trip Error-level alerting. The error is still returned
		// and surfaced as a FAILED action by the SDK.
		log.Warn(actionName+": modify failed", fields...)
		return nil, fmt.Errorf("ldap-connector: %s: failed to modify user %q: %w", actionName, acc.DN, err)
	}

	log.Info(actionName+": success", zap.String("dn", acc.DN), zap.Int("applied", len(changes)), zap.Strings("skipped", skipped))
	return &userAttrUpdate{DN: acc.DN, Applied: len(changes), Skipped: skipped}, nil
}

// updateUserAttrsResult builds the action return struct (success + applied + skipped).
func updateUserAttrsResult(applied int, skipped []string) *structpb.Struct {
	return actions.NewReturnValues(true,
		actions.NewNumberReturnField("applied", float64(applied)),
		actions.NewStringListReturnField("skipped", skipped),
	)
}

// assertDNInScope returns nil when target is equal to, or a descendant of, scope
// (case-insensitive). scope is canonicalized defensively since the stored config
// DN is not guaranteed canonical. Mirrors buildOUDN's fail-closed check.
func assertDNInScope(target, scope *ldap3.DN) error {
	if target == nil {
		return fmt.Errorf("nil target dn")
	}
	if scope == nil {
		return fmt.Errorf("no user-search-dn or base-dn configured")
	}
	rawScope := scope.String()
	canonScope, err := ldap.CanonicalizeDN(rawScope)
	if err != nil {
		return fmt.Errorf("invalid scope dn %q: %w", rawScope, err)
	}
	if !canonScope.EqualFold(target) && !canonScope.AncestorOfFold(target) {
		return fmt.Errorf("target %q is outside scope %q", target.String(), canonScope.String())
	}
	return nil
}

// resolveUpdateAttrName resolves a mask entry to a real LDAP attribute name. The
// second return is true for synthetic profile keys that map to no single attribute
// and should therefore be skipped.
func resolveUpdateAttrName(maskName string) (string, bool) {
	lower := strings.ToLower(maskName)
	if profileSyntheticSkip[lower] {
		return "", true
	}
	if alias, ok := profileAttrAliases[lower]; ok {
		return alias, false
	}
	return maskName, false
}

// buildUserAttrChanges turns the update mask into a set of LDAP Replace changes,
// reading current values from entry so already-satisfied changes are dropped
// (idempotent re-runs). actionName is used only in error messages (so a caller
// other than update_user_attrs, e.g. update_profile, doesn't tell the customer
// the wrong action name for a denylisted attribute). Rules:
//   - synthetic keys (login, path) -> skipped
//   - password* and objectClass    -> hard error (use credential rotation / not allowed)
//   - the target's RDN attribute(s) -> skipped (cannot be changed via Modify)
//   - a mask entry with no value in attrs -> skipped (attrs is looked up by
//     exact key match first, falling back to a case-insensitive match)
//   - the first mask entry that survives synthetic-skip/RDN/password-denylist/
//     missing-value filtering claims the attribute; later entries resolving to
//     the same attribute are skipped (the seen[lower] dedupe only fires after
//     those other gates -- a mask entry skipped by one of those gates does not
//     block a later entry for the same attribute)
//   - empty value -> clear (Replace with no values); skipped if already absent
//   - non-empty value -> Replace; skipped if the attribute already holds exactly it
//
// A multi-valued current attribute is collapsed to the single supplied value
// when set (not merged/reconciled) -- a known, deliberately deferred bug
// (logged at Warn here, not fixed). Today's collapse behavior is pinned by a
// TestBuildUserAttrChanges case so a future fix is a deliberate, reviewed change.
func buildUserAttrChanges(ctx context.Context, entry *ldap.Entry, targetDN *ldap3.DN, attrs map[string]string, mask []string, actionName string) ([]ldap3.Change, []string, error) {
	log := ctxzap.Extract(ctx)
	rdnTypes := rdnAttrTypes(targetDN)
	seen := map[string]bool{}
	var changes []ldap3.Change
	var skipped []string

	// Case-insensitive fallback index over attrs, built once. attrs[maskName] is
	// always tried first (exact match); this index only matters when a mask
	// entry's case doesn't exactly match its key in attrs (bug #3). If two attrs
	// keys fold to the same lowercase, the first one encountered during this
	// (map-order-random) build wins the fallback slot -- an intentionally
	// unspecified corner case since the caller controls attrs' keys.
	lowerAttrs := make(map[string]string, len(attrs))
	for k, v := range attrs {
		lk := strings.ToLower(k)
		if _, exists := lowerAttrs[lk]; !exists {
			lowerAttrs[lk] = v
		}
	}

	for _, maskName := range mask {
		attrName, skip := resolveUpdateAttrName(maskName)
		if skip {
			skipped = append(skipped, maskName)
			continue
		}

		if strings.Contains(strings.ToLower(attrName), "password") {
			return nil, nil, fmt.Errorf("attribute %q cannot be modified via %s; use credential rotation instead", maskName, actionName)
		}
		if strings.EqualFold(attrName, ldapAttrObjectClass) {
			return nil, nil, fmt.Errorf("attribute %q cannot be modified via %s", maskName, actionName)
		}

		if rdnTypes[strings.ToLower(attrName)] {
			// The RDN attribute value cannot be replaced in place (that requires
			// a ModifyDN); skip rather than fail an otherwise-valid batch.
			skipped = append(skipped, maskName)
			continue
		}

		value, ok := attrs[maskName]
		if !ok {
			value, ok = lowerAttrs[strings.ToLower(maskName)]
		}
		if !ok {
			skipped = append(skipped, maskName)
			continue
		}

		lower := strings.ToLower(attrName)
		if seen[lower] {
			skipped = append(skipped, maskName)
			continue
		}
		seen[lower] = true

		current := entry.GetEqualFoldAttributeValues(attrName)
		if value == "" {
			if len(current) == 0 {
				continue // already cleared
			}
			changes = append(changes, ldap3.Change{
				Operation:    ldap3.ReplaceAttribute,
				Modification: ldap3.PartialAttribute{Type: attrName},
			})
			continue
		}

		if len(current) > 1 {
			log.Warn(actionName+": multi-valued attribute will be collapsed to a single value",
				zap.String("attr", attrName), zap.Int("current_value_count", len(current)))
		}
		if len(current) == 1 && current[0] == value {
			continue // already set to exactly this value
		}
		changes = append(changes, ldap3.Change{
			Operation:    ldap3.ReplaceAttribute,
			Modification: ldap3.PartialAttribute{Type: attrName, Vals: []string{value}},
		})
	}

	return changes, skipped, nil
}

// rdnAttrTypes returns the lowercased attribute types that make up the entry's
// own (leftmost) RDN. ParseDN orders RDNs left-to-right, so RDNs[0] is the entry.
func rdnAttrTypes(dn *ldap3.DN) map[string]bool {
	out := map[string]bool{}
	if dn == nil || len(dn.RDNs) == 0 {
		return out
	}
	for _, attr := range dn.RDNs[0].Attributes {
		out[strings.ToLower(attr.Type)] = true
	}
	return out
}
