package connector

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	builder "github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/crypto"
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

var _ builder.AccountManager = &userResourceType{}
var _ builder.CredentialManager = &userResourceType{}

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

func (u *userResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	l.Debug("getting user", zap.String("resource_id", resourceId.Resource))

	userDN, err := ldap.CanonicalizeDN(resourceId.Resource)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap-connector: failed to canonicalize user DN: %w", err)
	}

	userEntries, _, err := u.client.LdapSearch(ctx, ldap3.ScopeBaseObject, userDN, userFilter, allAttrs, "", ResourcesPageSize)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap-connector: failed to get user: %w", err)
	}

	if len(userEntries) == 0 {
		return nil, nil, fmt.Errorf("ldap-connector: user not found")
	}

	userEntry := userEntries[0]

	ur, err := userResource(ctx, userEntry)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap-connector: failed to get user: %w", err)
	}

	return ur, nil, nil
}

func (u *userResourceType) Delete(ctx context.Context, resourceId *v2.ResourceId) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	l.Debug("deleting user", zap.String("resource_id", resourceId.Resource))

	userDN, err := ldap.CanonicalizeDN(resourceId.Resource)
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: failed to canonicalize user DN: %w", err)
	}

	deleteRequest := &ldap3.DelRequest{DN: userDN.String()}
	err = u.client.LdapDelete(ctx, deleteRequest)
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: failed to delete user: %w", err)
	}

	return nil, nil
}

func (u *userResourceType) Entitlements(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (u *userResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (o *userResourceType) CreateAccountCapabilityDetails(ctx context.Context) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	return &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_ENCRYPTED_PASSWORD,
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_RANDOM_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
	}, nil, nil
}

func (o *userResourceType) CreateAccount(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	credentialOptions *v2.LocalCredentialOptions,
) (
	builder.CreateAccountResponse,
	[]*v2.PlaintextData,
	annotations.Annotations,
	error,
) {
	l := ctxzap.Extract(ctx)

	if credentialOptions == nil {
		return nil, nil, nil, fmt.Errorf("baton-ldap: create-account: missing credential options")
	}

	dn, attrs, err := o.extractProfile(ctx, accountInfo)
	if err != nil {
		l.Error("baton-ldap: create-account failed to extract profile", zap.Error(err), zap.Any("accountInfo", accountInfo))
		return nil, nil, nil, err
	}

	user := &ldap3.AddRequest{
		DN:         dn,
		Attributes: attrs,
	}

	err = o.client.LdapAdd(ctx, user)
	if err != nil {
		l.Error("baton-ldap: create-account failed to create account", zap.Error(err), zap.Any("userParams", user))
		return nil, nil, nil, err
	}

	ptd, annos, err := o.setPassword(ctx, dn, credentialOptions)
	if err != nil {
		l.Error("baton-ldap: create-account failed to set password", zap.Error(err), zap.Any("accountInfo", accountInfo))
		return nil, nil, nil, err
	}

	acc, err := getAccount(ctx, o.client, dn)
	if err != nil {
		return nil, nil, nil, err
	}

	ur, err := userResource(ctx, acc)
	if err != nil {
		l.Error("baton-ldap: create-account failed to create resource", zap.Error(err), zap.Any("accountInfo", accountInfo))
		return nil, nil, nil, err
	}
	resp := &v2.CreateAccountResponse_SuccessResult{
		Resource: ur,
	}

	return resp, ptd, annos, nil
}

func (o *userResourceType) Rotate(ctx context.Context, resourceId *v2.ResourceId, credentialOptions *v2.LocalCredentialOptions) ([]*v2.PlaintextData, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	l.Debug("rotating user", zap.String("resource_id", resourceId.Resource))

	userDN, err := ldap.CanonicalizeDN(resourceId.Resource)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap-connector: failed to canonicalize user DN: %w", err)
	}

	ptd, annos, err := o.setPassword(ctx, userDN.String(), credentialOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap-connector: failed to set password: %w", err)
	}

	return ptd, annos, nil
}

func (o *userResourceType) RotateCapabilityDetails(ctx context.Context) (*v2.CredentialDetailsCredentialRotation, annotations.Annotations, error) {
	return &v2.CredentialDetailsCredentialRotation{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_ENCRYPTED_PASSWORD,
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_RANDOM_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_ENCRYPTED_PASSWORD,
	}, nil, nil
}

func (o *userResourceType) setPassword(
	ctx context.Context,
	dn string,
	credentialOptions *v2.LocalCredentialOptions,
) ([]*v2.PlaintextData, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("setting password for user", zap.String("dn", dn))

	acc, err := getAccount(ctx, o.client, dn)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap-connector: failed to get user: %w", err)
	}

	// These values are only if credentialOptions is NoPassword.
	password := ""
	// Delete password if credentialOptions is NoPassword.
	change := ldap3.Change{
		Operation: ldap3.DeleteAttribute,
		Modification: ldap3.PartialAttribute{
			Type: "userPassword",
		},
	}

	// Generate or use decrypted password based on credentialOptions.
	if credentialOptions.GetNoPassword() == nil {
		password, err = crypto.GeneratePassword(ctx, credentialOptions)
		if err != nil {
			l.Error("baton-ldap: failed to generate password", zap.Error(err), zap.Any("dn", dn))
			return nil, nil, err
		}
		change = ldap3.Change{
			Operation: ldap3.ReplaceAttribute,
			Modification: ldap3.PartialAttribute{
				Type: "userPassword",
				Vals: []string{password},
			},
		}
	}

	modifyRequest := &ldap3.ModifyRequest{
		DN:      acc.DN,
		Changes: []ldap3.Change{change},
	}
	err = o.client.LdapModify(ctx, modifyRequest)
	if err != nil {
		l.Error("baton-ldap: failed to set password", zap.Error(err), zap.Any("dn", dn))
		return nil, nil, err
	}
	ptd := []*v2.PlaintextData{
		{
			Name:        "password",
			Description: "The password for the user",
			Schema:      "string",
			Bytes:       []byte(password),
		},
	}

	return ptd, nil, nil
}

func (o *userResourceType) extractProfile(ctx context.Context, accountInfo *v2.AccountInfo) (string, []ldap3.Attribute, error) {
	l := ctxzap.Extract(ctx)

	prof := accountInfo.GetProfile()
	if prof == nil {
		return "", nil, fmt.Errorf("missing profile")
	}
	data := prof.AsMap()
	l.Debug("baton-ldap: create-account profile", zap.Any("data", data))

	suffix, ok := data["suffix"].(string)
	if !ok {
		return "", nil, fmt.Errorf("invalid/missing suffix")
	}
	path, ok := data["path"].(string)
	if !ok {
		return "", nil, fmt.Errorf("invalid/missing path")
	}
	rdnKey, ok := data["rdnKey"].(string)
	if !ok {
		return "", nil, fmt.Errorf("invalid/missing rdnKey")
	}
	rdnValue, ok := data["rdnValue"].(string)
	if !ok {
		return "", nil, fmt.Errorf("invalid/missing rdnValue")
	}

	calculatePosixUIDNumber := false
	if v, ok := data["calculatePosixUIDNumber"].(bool); ok {
		calculatePosixUIDNumber = v
	}

	var dn string
	if path != "" {
		dn = strings.Join([]string{fmt.Sprintf("%s=%s", rdnKey, rdnValue), path, suffix}, ",")
	} else {
		dn = strings.Join([]string{fmt.Sprintf("%s=%s", rdnKey, rdnValue), suffix}, ",")
	}

	isPosixAccount := false
	objectClass, ok := data["objectClass"].([]any)
	if !ok {
		return "", nil, fmt.Errorf("invalid/missing objectClass")
	}
	for _, oc := range objectClass {
		if s, ok := oc.(string); !ok {
			return "", nil, fmt.Errorf("invalid objectClass")
		} else if strings.EqualFold(s, "posixAccount") {
			isPosixAccount = true
		}
	}

	attrs := []ldap3.Attribute{}

	if calculatePosixUIDNumber && isPosixAccount {
		newUID, err := o.client.CalculateUIDNumber(ctx, o.userSearchDN, ResourcesPageSize)
		if err != nil {
			return "", nil, err
		}

		attrs = append(attrs, toAttr("uidNumber", newUID))
	}

	for k, v := range data {
		if slices.Contains([]string{
			"additionalAttributes",
			"rdnKey",
			"rdnValue",
			"path",
			"suffix",
			"login",
			"calculatePosixUIDNumber",
		}, k) {
			continue
		}

		attrs = append(attrs, toAttr(k, v))
	}

	additionalAttributes, ok := data["additionalAttributes"].(map[string]interface{})
	if ok {
		for k, v := range additionalAttributes {
			if calculatePosixUIDNumber && strings.EqualFold(k, "uidNumber") {
				continue
			}

			attrs = append(attrs, toAttr(k, v))
		}
	}

	l.Debug("baton-ldap: create-account attributes", zap.Any("attrs", attrs))

	return dn, attrs, nil
}

func getAccount(ctx context.Context, client *ldap.Client, dn string) (*ldap.Entry, error) {
	userEntry, err := client.LdapGetWithStringDN(ctx, dn, userFilter, allAttrs)
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: failed to get user: %w", err)
	}
	return userEntry, nil
}

func userBuilder(client *ldap.Client, userSearchDN *ldap3.DN, disableOperationalAttrs bool) *userResourceType {
	return &userResourceType{
		resourceType:            resourceTypeUser,
		userSearchDN:            userSearchDN,
		client:                  client,
		disableOperationalAttrs: disableOperationalAttrs,
	}
}
