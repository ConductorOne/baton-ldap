package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-ldap/pkg/config"
	"github.com/conductorone/baton-ldap/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

var (
	resourceTypeUser = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: annotationsForUserResourceType(),
	}
	resourceTypeGroup = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_GROUP,
		},
	}
	resourceTypeRole = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_ROLE,
		},
	}
)

type LDAP struct {
	client *ldap.Client
	config *config.Config
}

func (l *LDAP) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		userBuilder(l.client, l.config.UserSearchDN, l.config.DisableOperationalAttrs),
		groupBuilder(l.client, l.config.GroupSearchDN, l.config.UserSearchDN),
		roleBuilder(l.client, l.config.RoleSearchDN),
	}
}

func (l *LDAP) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "LDAP",
		// TODO: add better description
		Description: "LDAP connector for Baton",
	}, nil
}

// Validates that the user has read access to all relevant tables (more information in the readme).
func (l *LDAP) Validate(ctx context.Context) (annotations.Annotations, error) {
	_, _, err := l.client.LdapSearch(
		ctx,
		ldap3.ScopeBaseObject,
		nil,
		"(objectClass=*)",
		nil,
		"",
		1,
	)
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: failed to validate connection: %w", err)
	}
	return nil, nil
}

// New returns the LDAP connector.
func New(ctx context.Context, cf *config.Config) (*LDAP, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("creating new LDAP connector",
		zap.Stringer("server_url", cf.ServerURL),
		zap.Stringer("bind_dn", cf.BindDN),
		zap.Bool("disable_operational_attrs", cf.DisableOperationalAttrs))

	ldapClient, err := ldap.NewClient(ctx,
		cf.ServerURL.String(),
		cf.BindPassword,
		cf.BindDN.String(),
		cf.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}

	return &LDAP{
		client: ldapClient,
		config: cf,
	}, nil
}
