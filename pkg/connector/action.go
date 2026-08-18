package connector

import (
	"context"
	"errors"
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

	ldapAttrObjectClass = "objectClass"
)

// profileAttrAliases maps baton-ldap's synthetic user-profile keys (produced by
// userResource) to the real LDAP attribute they represent. A mask name not in
// this map (and not in profileSyntheticSkip) is treated as a raw LDAP attribute
// name. Keys are compared case-insensitively.
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

// GlobalActions registers the connector's global actions. The SDK detects this
// via type assertion in NewConnector and serves the registered actions.
func (l *LDAP) GlobalActions(ctx context.Context, registry actions.ActionRegistry) error {
	if err := registry.Register(ctx, createOUActionSchema(), l.createOU); err != nil {
		return fmt.Errorf("ldap-connector: failed to register create_ou action: %w", err)
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
// fetch -> diff -> modify pipeline behind updateProfile (the resource-scoped
// action). It always runs this complete pipeline with no empty-mask/empty-attrs
// early return of its own: updateProfile needs the full pipeline to run even
// for an empty mask, so a vanished/out-of-scope user still surfaces as
// NotFound instead of a false success.
//
// Status codes are deliberately identical regardless of caller: InvalidArgument
// for a malformed resourceID, NotFound for an out-of-scope or missing user
// (deliberately indistinguishable, to avoid leaking the existence of entries
// outside the connector's managed subtree), and — for a real server modify
// rejection — the code ldapResultCodeToGRPC derives from the server's LDAP
// result code. actionName only varies message text, never the status code.
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

	changes, skipped, err := buildUserAttrChanges(acc, targetDN, attrs, mask, actionName)
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
		return nil, status.Errorf(ldapResultCodeToGRPC(err), "ldap-connector: %s: failed to modify user %q: %v", actionName, acc.DN, err)
	}

	log.Info(actionName+": success", zap.String("dn", acc.DN), zap.Int("applied", len(changes)), zap.Strings("skipped", skipped))
	return &userAttrUpdate{DN: acc.DN, Applied: len(changes), Skipped: skipped}, nil
}

// ldapResultCodeToGRPC maps the LDAP protocol result code carried by err (RFC
// 4511 section 4.1.9, surfaced by go-ldap as *ldap3.Error.ResultCode) to the
// gRPC code that best describes whether retrying the operation could succeed.
// Without this, every server-side rejection reaches the SDK as an
// undifferentiated error and a transient "server busy" is indistinguishable
// from a permanent "permission denied".
//
// Only the codes a write can realistically hit are enumerated; anything else
// (including a non-LDAP error, or a nil error) falls through to codes.Unknown.
// Unknown is deliberate rather than arbitrary: it is exactly what the rest of
// this package's LDAP failure paths already produce today (createOU's bare
// fmt.Errorf wraps, for instance, since baton-sdk's finishTask defaults a
// non-status error to codes.Unknown), so unmapped result codes keep their
// current classification and only the mapped ones become more specific.
//
// Note that go-ldap reports transport failures as the pseudo result code
// ErrorNetwork (200) rather than a real protocol code; the ldap client already
// retries those in-process, so one reaching here means its retries were
// exhausted, which is still a transient condition worth reporting as such.
func ldapResultCodeToGRPC(err error) codes.Code {
	var ldapErr *ldap3.Error
	if !errors.As(err, &ldapErr) {
		return codes.Unknown
	}

	switch ldapErr.ResultCode {
	// Transient: the directory is up but momentarily refusing work, or the
	// connection failed. A later attempt can plausibly succeed.
	case ldap3.LDAPResultBusy, ldap3.LDAPResultUnavailable, ldap3.ErrorNetwork:
		return codes.Unavailable
	case ldap3.LDAPResultTimeLimitExceeded:
		return codes.DeadlineExceeded

	// Server-imposed limits. Retryable in principle, but only after the limit
	// window resets rather than immediately.
	case ldap3.LDAPResultAdminLimitExceeded, ldap3.LDAPResultSizeLimitExceeded:
		return codes.ResourceExhausted

	// Terminal: the bind identity is not permitted to make this change.
	case ldap3.LDAPResultInsufficientAccessRights, ldap3.LDAPResultStrongAuthRequired,
		ldap3.LDAPResultConfidentialityRequired:
		return codes.PermissionDenied
	case ldap3.LDAPResultInvalidCredentials, ldap3.LDAPResultInappropriateAuthentication:
		return codes.Unauthenticated

	// Terminal: the entry is gone. Distinct from the pre-flight NotFound above,
	// which covers a lookup that failed before any modify was attempted.
	case ldap3.LDAPResultNoSuchObject:
		return codes.NotFound

	// Terminal: the request itself is malformed or violates the schema. Retrying
	// the identical modify will fail identically.
	case ldap3.LDAPResultObjectClassViolation, ldap3.LDAPResultConstraintViolation,
		ldap3.LDAPResultInvalidAttributeSyntax, ldap3.LDAPResultUndefinedAttributeType,
		ldap3.LDAPResultInvalidDNSyntax, ldap3.LDAPResultNotAllowedOnRDN:
		return codes.InvalidArgument

	// Terminal: well-formed and permitted, but the server declines in this state
	// (read-only replica, DIT constraint, policy plugin).
	case ldap3.LDAPResultUnwillingToPerform:
		return codes.FailedPrecondition

	default:
		return codes.Unknown
	}
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
// (idempotent re-runs). actionName is used only in error messages, so the
// caller (e.g. update_profile) is named accurately in a denylisted-attribute
// error. Rules:
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
//   - non-empty value on a single-valued (or absent) attribute -> Replace;
//     skipped if the attribute already holds exactly it
//   - non-empty value on an attribute that currently holds MORE THAN ONE
//     value -> hard error; replacing would silently discard every other
//     existing value with no visible signal to the caller. Clearing (empty
//     value) a multi-valued attribute is unaffected and still succeeds --
//     that is an explicit, intentional "remove all values" operation, not
//     data loss.
func buildUserAttrChanges(entry *ldap.Entry, targetDN *ldap3.DN, attrs map[string]string, mask []string, actionName string) ([]ldap3.Change, []string, error) {
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
			// Replacing a multi-valued attribute with a single value would
			// silently discard every other existing value with no visible
			// signal to the caller. Abort the whole batch instead of
			// collapsing, matching the password/objectClass denylist checks
			// above.
			return nil, nil, fmt.Errorf("attribute %q has %d existing values; refusing to replace them with a single value via %s (clear the attribute first if this is intentional)",
				maskName, len(current), actionName)
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
