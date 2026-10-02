package connector

import (
	"context"
	"fmt"
	"strings"

	"github.com/conductorone/baton-ldap/pkg/config"
	"github.com/conductorone/baton-ldap/pkg/ldap"
	config_sdk "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	actionNameCreateGroup = "create_group"

	returnFieldCreated = "created"
	returnFieldGroupDN = "group_dn"
	returnFieldGroup   = "group"
)

var createGroupReadBackAttrs = []string{attrGroupCommonName, attrGroupDescription, attrGroupIdPosix, ldapAttrObjectClass}

func buildGroupDN(name, parentDN string, scopeDN *ldap3.DN) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if scopeDN == nil {
		return "", fmt.Errorf("group-search-dn must be configured")
	}
	rawScope := scopeDN.String()
	scope, err := ldap.CanonicalizeDN(rawScope)
	if err != nil {
		return "", fmt.Errorf("invalid group-search-dn %q: %w", rawScope, err)
	}

	parentDN = strings.TrimSpace(parentDN)
	parent := scope
	if parentDN != "" {
		parent, err = ldap.CanonicalizeDN(parentDN)
		if err != nil {
			return "", fmt.Errorf("invalid parent_dn %q: %w", parentDN, err)
		}
	}

	if err := assertDNInScope(parent, scope); err != nil {
		return "", fmt.Errorf("parent_dn %q is outside the configured group-search-dn %q", parent.String(), scope.String())
	}

	return fmt.Sprintf("%s=%s,%s", attrGroupCommonName, ldap3.EscapeDN(name), parent.String()), nil
}

func memberAttributeForObjectClass(objectClass string) string {
	if objectClass == config.CreateGroupObjectClassGroupOfNames {
		return attrGroupMember
	}
	return attrGroupUniqueMember
}

func isGroupEntry(entry *ldap.Entry) bool {
	for _, objectClass := range entry.GetEqualFoldAttributeValues(ldapAttrObjectClass) {
		for name, resourceType := range objectClassesToResourceTypes {
			if resourceType == resourceTypeGroup && strings.EqualFold(name, objectClass) {
				return true
			}
		}
	}
	return false
}

func canHoldPinnedMemberAttribute(entry *ldap.Entry, groupMemberAttribute, requiredObjectClass string) bool {
	switch groupMemberAttribute {
	case config.GroupMemberAttributeMember, config.GroupMemberAttributeUniqueMember:
	default:
		return true
	}
	for _, objectClass := range entry.GetEqualFoldAttributeValues(ldapAttrObjectClass) {
		if strings.EqualFold(objectClass, requiredObjectClass) {
			return true
		}
	}
	return false
}

func createGroupActionSchema() *v2.BatonActionSchema {
	return &v2.BatonActionSchema{
		Name:        actionNameCreateGroup,
		DisplayName: "Create Group",
		Description: "Create an LDAP group under a parent container within the configured group search DN.",
		ActionType:  []v2.ActionType{v2.ActionType_ACTION_TYPE_RESOURCE_CREATE},
		Arguments: []*config_sdk.Field{
			{
				Name:        argName,
				DisplayName: "Name",
				Description: "The group name (used as the cn attribute and RDN).",
				IsRequired:  true,
				Field:       &config_sdk.Field_StringField{StringField: &config_sdk.StringField{}},
			},
			{
				Name:        argParentDN,
				DisplayName: "Parent DN",
				Description: "The container DN under which to create the group. Defaults to the configured group search DN if empty.",
				Field:       &config_sdk.Field_StringField{StringField: &config_sdk.StringField{}},
			},
			{
				Name:        argDescription,
				DisplayName: "Description",
				Description: "Optional description attribute for the group.",
				Field:       &config_sdk.Field_StringField{StringField: &config_sdk.StringField{}},
			},
		},
		ReturnTypes: []*config_sdk.Field{
			{
				Name:        "success",
				DisplayName: "Success",
				Field:       &config_sdk.Field_BoolField{BoolField: &config_sdk.BoolField{}},
			},
			{
				Name:        returnFieldCreated,
				DisplayName: "Created",
				Description: "True when this call created the group; false when a group already existed at the DN.",
				Field:       &config_sdk.Field_BoolField{BoolField: &config_sdk.BoolField{}},
			},
			{
				Name:        returnFieldGroupDN,
				DisplayName: "Group DN",
				Description: "The distinguished name of the group, as the directory returns it.",
				Field:       &config_sdk.Field_StringField{StringField: &config_sdk.StringField{}},
			},
			{
				Name:        returnFieldGroup,
				DisplayName: "Group",
				Description: "The group resource, as sync reports it.",
				Field:       &config_sdk.Field_ResourceField{ResourceField: &config_sdk.ResourceField{}},
			},
		},
	}
}

func (l *LDAP) createGroup(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	log := ctxzap.Extract(ctx)

	objectClass, err := config.ResolveCreateGroupObjectClass(l.config.GroupMemberAttribute, l.config.CreateGroupObjectClass)
	if err != nil {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "ldap-connector: create_group: %v", err)
	}

	name, err := actions.RequireStringArg(args, argName)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "ldap-connector: create_group: %v", err)
	}
	name = strings.TrimSpace(name)
	parentArg, _ := actions.GetStringArg(args, argParentDN)
	description, _ := actions.GetStringArg(args, argDescription)
	description = strings.TrimSpace(description)

	groupDN, err := buildGroupDN(name, parentArg, l.config.GroupSearchDN)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "ldap-connector: create_group: %v", err)
	}

	log.Debug("creating group", zap.String("dn", groupDN), zap.String("object_class", objectClass))

	addReq := ldap3.NewAddRequest(groupDN, nil)
	addReq.Attribute(ldapAttrObjectClass, []string{ldapObjectClassTop, objectClass})
	addReq.Attribute(attrGroupCommonName, []string{name})
	if description != "" {
		addReq.Attribute(attrGroupDescription, []string{description})
	}
	placeholder := l.config.CreateGroupPlaceholderMember
	if placeholder != nil {
		addReq.Attribute(memberAttributeForObjectClass(objectClass), []string{placeholder.String()})
	}

	created := true
	var memberRequiredErr error
	if err := l.client.LdapAddStrict(ctx, addReq); err != nil {
		switch {
		case ldap3.IsErrorWithCode(err, ldap3.LDAPResultEntryAlreadyExists):
			created = false
		case ldap3.IsErrorWithCode(err, ldap3.LDAPResultObjectClassViolation) && placeholder == nil:
			created = false
			memberRequiredErr = err
		default:
			log.Warn("create_group: add failed", zap.String("dn", groupDN), zap.Error(err))
			return nil, nil, status.Errorf(ldapResultCodeToGRPC(err), "ldap-connector: create_group: failed to add group %q: %v", groupDN, err)
		}
	}

	entry, err := l.client.LdapGetRaw(ctx, groupDN, ldapFilterAnyObject, createGroupReadBackAttrs)
	if err != nil {
		if memberRequiredErr != nil && lookupErrToGRPC(err) == codes.NotFound {
			log.Warn("create_group: schema requires a member", zap.String("dn", groupDN), zap.Error(memberRequiredErr))
			return nil, nil, status.Errorf(codes.InvalidArgument,
				"ldap-connector: create_group: this directory's schema requires at least one member for %s; set create-group-placeholder-member: %v",
				objectClass, memberRequiredErr)
		}
		log.Warn("create_group: read-back failed", zap.String("dn", groupDN), zap.Error(err))
		return nil, nil, status.Errorf(lookupErrToGRPC(err), "ldap-connector: create_group: failed to read group %q: %v", groupDN, err)
	}
	if !isGroupEntry(entry) {
		return nil, nil, status.Errorf(codes.AlreadyExists, "ldap-connector: create_group: an entry that is not a group already exists at %q", entry.DN)
	}
	if !created && !canHoldPinnedMemberAttribute(entry, l.config.GroupMemberAttribute, objectClass) {
		return nil, nil, status.Errorf(codes.FailedPrecondition,
			"ldap-connector: create_group: the group at %q is not a %s, so it cannot hold group-member-attribute %s",
			entry.DN, objectClass, l.config.GroupMemberAttribute)
	}

	resource, err := groupResource(ctx, entry)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "ldap-connector: create_group: failed to build group resource for %q: %v", entry.DN, err)
	}
	groupField, err := actions.NewResourceReturnField(returnFieldGroup, resource)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "ldap-connector: create_group: %v", err)
	}

	log.Info("create_group: success", zap.String("dn", entry.DN), zap.Bool("created", created))

	return actions.NewReturnValues(true,
		actions.NewBoolReturnField(returnFieldCreated, created),
		actions.NewStringReturnField(returnFieldGroupDN, entry.DN),
		groupField,
	), nil, nil
}
