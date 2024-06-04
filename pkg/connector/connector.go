package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-ldap/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
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
	client                  *ldap.Client
	disableOperationalAttrs bool
}

func (l *LDAP) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		userBuilder(l.client, l.disableOperationalAttrs),
		groupBuilder(l.client),
		roleBuilder(l.client),
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
		"(objectClass=*)",
		nil,
		"",
		1,
		"",
	)
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: failed to validate user credentials: %w", err)
	}
	return nil, nil
}

// New returns the LDAP connector.
func New(ctx context.Context, serverUrl string, baseDN string, password string, userDN string, disableOperationalAttrs bool, insecureSkipVerify bool) (*LDAP, error) {
	l := ctxzap.Extract(ctx)

	l.Debug("creating new LDAP connector", zap.String("serverUrl", serverUrl), zap.String("baseDN", baseDN), zap.Bool("disableOperationalAttrs", disableOperationalAttrs))
	conn, err := ldap.TestConnection(serverUrl, insecureSkipVerify)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	ldapClient, err := ldap.NewClient(ctx, serverUrl, baseDN, password, userDN, insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	return &LDAP{
		client:                  ldapClient,
		disableOperationalAttrs: disableOperationalAttrs,
	}, nil
}
