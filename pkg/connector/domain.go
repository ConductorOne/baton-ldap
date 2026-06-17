package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-ldap/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"

	ldap3 "github.com/go-ldap/ldap/v3"
)

const (
	domainFilter = "(|(objectClass=domain)(objectClass=domainDNS))"

	attrDomainName        = "dc"
	attrDomainDescription = "description"
)

type domainResourceType struct {
	resourceType *v2.ResourceType
	client       *ldap.Client
	baseDN       *ldap3.DN
}

func (d *domainResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return d.resourceType
}

func domainResource(_ context.Context, entry *ldap.Entry) (*v2.Resource, error) {
	rdn, err := ldap.CanonicalizeDN(entry.DN)
	if err != nil {
		return nil, err
	}
	entryDN := rdn.String()

	displayName := entry.GetEqualFoldAttributeValue(attrDomainName)
	if displayName == "" {
		displayName = entryDN
	}

	description := entry.GetEqualFoldAttributeValue(attrDomainDescription)

	var opts []rs.ResourceOption
	if description != "" {
		opts = append(opts, rs.WithDescription(description))
	}

	resource, err := rs.NewResource(
		displayName,
		resourceTypeDomain,
		entryDN,
		opts...,
	)
	if err != nil {
		return nil, err
	}
	return resource, nil
}

func (d *domainResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: resourceTypeDomain.Id})
	if err != nil {
		return nil, "", nil, err
	}

	entries, nextPage, err := d.client.LdapSearch(
		ctx,
		ldap3.ScopeWholeSubtree,
		d.baseDN,
		domainFilter,
		nil,
		page,
		ResourcesPageSize,
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ldap-connector: failed to list domains: %w", err)
	}

	pageToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	var rv []*v2.Resource
	for _, entry := range entries {
		entryCopy := entry
		dr, err := domainResource(ctx, entryCopy)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, dr)
	}

	return rv, pageToken, nil, nil
}

func (d *domainResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (d *domainResourceType) Grants(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func domainBuilder(client *ldap.Client, baseDN *ldap3.DN) *domainResourceType {
	return &domainResourceType{
		resourceType: resourceTypeDomain,
		client:       client,
		baseDN:       baseDN,
	}
}
