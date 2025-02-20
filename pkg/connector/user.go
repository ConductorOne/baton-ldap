package connector

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	mapset "github.com/deckarep/golang-set/v2"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"

	"github.com/conductorone/baton-ldap/pkg/ldap"
)

// InetOrgPerson resource structure
// https://datatracker.ietf.org/doc/html/rfc2798
const (
	userObjectClasses     = "(objectClass=inetOrgPerson)(objectClass=person)(objectClass=user)(objectClass=organizationalPerson)"
	userFilter            = "(|" + userObjectClasses + ")"
	attrUserUID           = "uid"
	attrUserCommonName    = "cn"
	attrFirstName         = "givenName"
	attrLastName          = "sn"
	attrUserMail          = "mail"
	attrUserDisplayName   = "displayName"
	attrUserCreatedAt     = "createTimestamp"
	attrUserAuthTimestamp = "authTimestamp"
	attrObjectGUID        = "objectGUID"

	// Microsoft active directory specific attribute.
	attrsAMAccountName     = "sAMAccountName"
	attrUserPrincipalName  = "userPrincipalName"
	attrUserAccountControl = "userAccountControl"
	attrUserLastLogon      = "lastLogonTimestamp"

	// FreeIPA (Red Hat Identity) specific attributes.
	attrNSAccountLock = "nsAccountLock"
)

var allAttrs = []string{"*", "+"}

type userResourceType struct {
	resourceType            *v2.ResourceType
	client                  *ldap.Client
	userSearchDN            *ldap3.DN
	disableOperationalAttrs bool
}

func (u *userResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return u.resourceType
}

func parseUserNames(user *ldap.Entry) (string, string, string) {
	fullName := user.GetEqualFoldAttributeValue(attrUserCommonName)
	firstName := user.GetEqualFoldAttributeValue(attrFirstName)
	lastName := user.GetEqualFoldAttributeValue(attrLastName)
	displayName := user.GetEqualFoldAttributeValue(attrUserDisplayName)

	if firstName == "" || lastName == "" {
		firstName, lastName = splitFullName(fullName)
	}

	if displayName == "" {
		displayName = fullName
	}

	return firstName, lastName, displayName
}

func parseUserStatus(user *ldap.Entry) (v2.UserTrait_Status_Status, error) {
	userStatus := v2.UserTrait_Status_STATUS_UNSPECIFIED

	// Currently only UserAccountControlFlag from Microsoft or nsAccountLock from FreeIPA is supported
	userAccountControlFlag := user.GetEqualFoldAttributeValue(attrUserAccountControl)
	nsAccountLockFlag := user.GetEqualFoldAttributeValue(attrNSAccountLock)

	if userAccountControlFlag != "" {
		userAccountControlFlag, err := strconv.ParseInt(userAccountControlFlag, 10, 64)
		if err != nil {
			return userStatus, err
		}
		// Check if the ACCOUNTDISABLE flag (bit 2) is set
		// https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
		if (userAccountControlFlag & 2) == 0 {
			userStatus = v2.UserTrait_Status_STATUS_ENABLED
		} else {
			userStatus = v2.UserTrait_Status_STATUS_DISABLED
		}
		return userStatus, nil
	} else if nsAccountLockFlag != "" {
		locked, _ := strconv.ParseBool(nsAccountLockFlag)
		if locked {
			userStatus = v2.UserTrait_Status_STATUS_DISABLED
		} else {
			userStatus = v2.UserTrait_Status_STATUS_ENABLED
		}
	}

	return userStatus, nil
}

func parseUserLogin(user *ldap.Entry) (string, []string) {
	login := ""
	aliases := mapset.NewSet[string]()

	sAMAccountName := user.GetEqualFoldAttributeValue(attrsAMAccountName)
	uid := user.GetEqualFoldAttributeValue(attrUserUID)
	cn := user.GetEqualFoldAttributeValue(attrUserCommonName)
	principalName := user.GetEqualFoldAttributeValue(attrUserPrincipalName)
	guid := user.GetEqualFoldAttributeValue(attrObjectGUID)

	for _, attr := range []string{sAMAccountName, uid, cn, principalName, guid} {
		if attr == "" || containsBinaryData(attr) {
			continue
		}
		if login == "" {
			login = attr
			continue
		}
		aliases.Add(attr)
	}
	aliases.Remove(login)

	return login, aliases.ToSlice()
}

func parseUserLastLogin(lastLoginStr string) (*time.Time, error) {
	lastLoginTime, err := time.Parse("20060102150405Z0700", lastLoginStr)
	if err == nil {
		lastLoginTime = lastLoginTime.UTC()
		return &lastLoginTime, nil
	}

	// Number of 100 nanosecond intervals since 1601: https://learn.microsoft.com/en-us/windows/win32/adschema/a-lastlogontimestamp
	lastLoginInt, err := strconv.ParseInt(lastLoginStr, 10, 64)
	if err != nil {
		return nil, err
	}
	lastLoginInt /= 10_000_000     // convert to seconds
	lastLoginInt -= 11_644_473_600 // seconds from 1601 to 1970
	lastLoginTime = time.Unix(lastLoginInt, 0).UTC()

	return &lastLoginTime, nil
}

func containsBinaryData(value string) bool {
	for _, c := range value {
		if c < 32 || c > 126 {
			return true
		}
	}
	return false
}

// Create a new connector resource for an LDAP User.
func userResource(ctx context.Context, user *ldap.Entry) (*v2.Resource, error) {
	l := ctxzap.Extract(ctx)

	firstName, lastName, displayName := parseUserNames(user)
	userId := user.GetEqualFoldAttributeValue(attrUserUID)

	udn, err := ldap.CanonicalizeDN(user.DN)
	if err != nil {
		return nil, err
	}
	userDN := udn.String()

	profile := map[string]interface{}{
		"user_id":    userId,
		"first_name": firstName,
		"last_name":  lastName,
		"path":       userDN,
	}

	for _, v := range user.Attributes {
		// skip userPassword, msSFU30Password, etc
		if strings.Contains(strings.ToLower(v.Name), "password") {
			continue
		}

		if len(v.Values) == 1 && !containsBinaryData(v.Values[0]) {
			profile[v.Name] = v.Values[0]
		}
	}

	userStatus, err := parseUserStatus(user)
	if err != nil {
		return nil, err
	}

	// If the user status is not set, default to enabled
	if userStatus == v2.UserTrait_Status_STATUS_UNSPECIFIED {
		userStatus = v2.UserTrait_Status_STATUS_ENABLED
	}

	userTraitOptions := []rs.UserTraitOption{
		rs.WithEmail(user.GetEqualFoldAttributeValue(attrUserMail), true),
		rs.WithStatus(userStatus),
	}

	rawObjectClasses := user.GetEqualFoldAttributeValues("objectClass")
	objectClasses := make([]string, 0, len(rawObjectClasses))
	for _, objectClass := range rawObjectClasses {
		objectClasses = append(objectClasses, strings.ToLower(objectClass))
	}
	switch {
	case slices.Contains(objectClasses, "computer"), slices.Contains(objectClasses, "msds-managedserviceaccount"):
		userTraitOptions = append(userTraitOptions, rs.WithAccountType(v2.UserTrait_ACCOUNT_TYPE_SERVICE))
	case slices.Contains(objectClasses, "person"):
		userTraitOptions = append(userTraitOptions, rs.WithAccountType(v2.UserTrait_ACCOUNT_TYPE_HUMAN))
	default:
		userTraitOptions = append(userTraitOptions, rs.WithAccountType(v2.UserTrait_ACCOUNT_TYPE_UNSPECIFIED))
	}

	login, aliases := parseUserLogin(user)
	if login != "" {
		userTraitOptions = append(userTraitOptions, rs.WithUserLogin(login, aliases...))
		profile["login"] = login
	}

	userTraitOptions = append(userTraitOptions, rs.WithUserProfile(profile))

	createdAt := user.GetEqualFoldAttributeValue(attrUserCreatedAt)
	createTime, err := time.Parse("20060102150405Z0700", createdAt)
	if err == nil {
		userTraitOptions = append(userTraitOptions, rs.WithCreatedAt(createTime))
	}

	// Try openldap format first, then fall back to Active Directory's format
	lastLogin, err := parseUserLastLogin(user.GetEqualFoldAttributeValue(attrUserLastLogon))
	if err != nil {
		lastLogin, _ = parseUserLastLogin(user.GetEqualFoldAttributeValue(attrUserAuthTimestamp))
	}
	if lastLogin != nil {
		userTraitOptions = append(userTraitOptions, rs.WithLastLogin(*lastLogin))
	}

	// if no display name, use the user id
	if displayName == "" {
		displayName = userId
	}

	l.Debug("creating user resource", zap.String("display_name", displayName), zap.String("user_id", userId), zap.String("user_dn", userDN))

	resource, err := rs.NewUserResource(
		displayName,
		resourceTypeUser,
		userDN,
		userTraitOptions,
	)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func (u *userResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	bag, page, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, err
	}

	attrs := allAttrs
	if u.disableOperationalAttrs {
		attrs = []string{"*"}
	}

	userEntries, nextPage, err := u.client.LdapSearch(
		ctx,
		ldap3.ScopeWholeSubtree,
		u.userSearchDN,
		userFilter,
		attrs,
		page,
		ResourcesPageSize,
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ldap-connector: failed to list users: %w", err)
	}

	pageToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	var rv []*v2.Resource
	for _, userEntry := range userEntries {
		l.Debug("processing user", zap.String("dn", userEntry.DN))
		ur, err := userResource(ctx, userEntry)
		if err != nil {
			return nil, pageToken, nil, err
		}

		rv = append(rv, ur)
	}

	return rv, pageToken, nil, nil
}

func (u *userResourceType) Entitlements(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (u *userResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func userBuilder(client *ldap.Client, userSearchDN *ldap3.DN, disableOperationalAttrs bool) *userResourceType {
	return &userResourceType{
		resourceType:            resourceTypeUser,
		userSearchDN:            userSearchDN,
		client:                  client,
		disableOperationalAttrs: disableOperationalAttrs,
	}
}
