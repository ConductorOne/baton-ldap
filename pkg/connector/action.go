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
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	ldapObjectClassOU    = "organizationalUnit"
	ldapAttrOU           = "ou"
	ldapAttrDescription  = "description"
	actionNameCreateOU   = "create_ou"
	argName              = "name"
	argParentDN          = "parent_dn"
	argDescription       = "description"
)

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
	canonBase, err := ldap.CanonicalizeDN(baseDN.String())
	if err != nil {
		return "", fmt.Errorf("invalid base-dn %q: %w", baseDN.String(), err)
	}
	baseDN = canonBase

	parentDN = strings.TrimSpace(parentDN)
	parent := baseDN
	if parentDN != "" {
		p, err := ldap.CanonicalizeDN(parentDN)
		if err != nil {
			return "", fmt.Errorf("invalid parent_dn %q: %w", parentDN, err)
		}
		parent = p
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

	name := strings.TrimSpace(args.GetFields()[argName].GetStringValue())
	parentArg := args.GetFields()[argParentDN].GetStringValue()
	description := strings.TrimSpace(args.GetFields()[argDescription].GetStringValue())

	ouDN, err := buildOUDN(name, parentArg, l.config.BaseDN)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap-connector: create_ou: %w", err)
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

	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"ou_dn":   structpb.NewStringValue(ouDN),
			"success": structpb.NewBoolValue(true),
		},
	}, nil, nil
}
