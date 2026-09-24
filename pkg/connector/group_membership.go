package connector

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/conductorone/baton-ldap/pkg/config"
	"github.com/conductorone/baton-ldap/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// This file owns the group membership write path: which attribute a membership
// belongs in, how it is written, and how the write is confirmed.
//
// The rule is read, decide, attempt, verify. Nothing here models a directory's
// schema: the entry says which membership attributes it uses, the server's own
// answer to a write says which ones it permits, and the read path's resolution
// says whether the membership is now there. objectClass alone cannot decide it --
// the same class set means different things on OpenLDAP, 389 DS, FreeIPA and
// Active Directory, and the client that reads the directory (SSSD with
// ldap_schema=rfc2307 vs rfc2307bis, for example) has its own opinion about which
// attribute holds membership.

// membershipAttrs are the attributes the read path unions (Grants) and the only
// ones this connector reads or writes membership in.
var membershipAttrs = []string{attrGroupMember, attrGroupUniqueMember, attrGroupMemberPosix}

// documentedOrder is the order used when several membership attributes are
// populated or when the entry shows nothing at all. `member` is the RFC 4519 name
// and the one rfc2307bis clients read.
var documentedOrder = []string{attrGroupMember, attrGroupUniqueMember, attrGroupMemberPosix}

// dnGroupClasses are the group classes that store membership as DNs, as opposed
// to posixGroup's memberUid. A group carrying any of these alongside posixGroup
// (rfc2307bis) has two legal membership attributes, and only the entry's content
// can say which one this directory uses.
var dnGroupClasses = []string{"groupOfNames", "groupOfUniqueNames", "group", "groupOfMembers"}

// otherDNGroupClasses are dnGroupClasses other than groupOfUniqueNames, used to
// tell "a groupOfUniqueNames group" (uniqueMember) from "a group that happens to
// carry both new-style and unique-name classes".
var otherDNGroupClasses = []string{"groupOfNames", "group", "groupOfMembers"}

// groupMembershipState is what the decision needs from the group entry the read
// path already fetched, plus what the principal's identity contributes.
type groupMembershipState struct {
	objectClasses []string

	// current membership values, by attribute
	member       []string
	uniqueMember []string
	memberUID    []string

	// principalIn lists the membership attributes whose stored values name the
	// principal, in documented order. Direct values only: a value that resolves to
	// another group is an inherited membership, not this group's own.
	principalIn []string

	// principalValues holds, per attribute in principalIn, the exact stored value
	// strings that matched. A revoke deletes those strings verbatim, because
	// whether a value is present is the server's matching rule and not our string
	// comparison, so the string sent back has to be the one the server returned.
	principalValues map[string][]string
}

// groupMembershipPlan is the decision.
type groupMembershipPlan struct {
	// dynamic is true for a groupOfURLs group: membership is computed from a URL,
	// not written.
	dynamic bool
	// inferred is true when the entry showed no membership at all, so the
	// attribute order came from the objectClass-informed fallback and is a guess.
	// Callers log it, and a grant treats it as candidates to try in order.
	inferred bool
	// present is true when the principal is already a direct member.
	present bool
	// targets are the attributes to act on, in order:
	//   - present -> every attribute that actually holds the principal (revoke)
	//   - otherwise -> the grant's targets (revoke never reaches a plan without
	//     present; see Revoke)
	targets []string
}

// planGroupMembership decides which attributes a membership belongs in.
//
// The order of the rules is the order of the evidence: what the class says about
// the group's very nature, then what the entry actually holds, then what its
// classes suggest when it holds nothing.
func planGroupMembership(s groupMembershipState) groupMembershipPlan {
	hasClass := func(want string) bool {
		return slices.ContainsFunc(s.objectClasses, func(oc string) bool {
			return strings.EqualFold(oc, want)
		})
	}
	hasAnyDNClass := slices.ContainsFunc(dnGroupClasses, hasClass)
	hasOtherDNClass := slices.ContainsFunc(otherDNGroupClasses, hasClass)

	// Rule 1: a dynamic group's membership is computed from memberURL. The
	// spelling is exact, deliberately: the read path tests the same string the
	// same way (Grants), so a lowercased spelling already reads as a static group,
	// and matching case-insensitively here would make read and write disagree
	// about such an entry.
	if hasClass(objectClassGroupOfURLs) {
		return groupMembershipPlan{dynamic: true}
	}

	// Rule 2: the principal is already there. That is the truth about where this
	// group keeps the membership, and for a revoke it is the target.
	if len(s.principalIn) > 0 {
		return groupMembershipPlan{present: true, targets: sortedByDocumentedOrder(s.principalIn)}
	}

	// Rule 3 and 4: the entry's own content is the strongest available signal of
	// which attribute this directory actually uses. One populated attribute is the
	// answer; several mean the entry's two consumer views have diverged, and both
	// are maintained.
	if populated := s.populated(); len(populated) > 0 {
		return groupMembershipPlan{targets: populated}
	}

	// Rule 5: nothing in the entry to learn from, so fall back to what its classes
	// suggest. Everything from here is a documented guess, which the caller logs.
	switch {
	case hasClass("groupOfUniqueNames") && !hasOtherDNClass:
		return groupMembershipPlan{inferred: true, targets: []string{attrGroupUniqueMember, attrGroupMember, attrGroupMemberPosix}}
	case hasClass("posixGroup") && !hasAnyDNClass:
		return groupMembershipPlan{inferred: true, targets: []string{attrGroupMemberPosix, attrGroupMember, attrGroupUniqueMember}}
	default:
		return groupMembershipPlan{inferred: true, targets: slices.Clone(documentedOrder)}
	}
}

// populated returns the membership attributes that currently hold values, in
// documented order. An entry with values in more than one attribute is one whose
// two consumer classes have diverged (POSIX clients read memberUid, DN clients
// read member), and both are written.
func (s groupMembershipState) populated() []string {
	var rv []string
	for _, attr := range documentedOrder {
		if len(s.values(attr)) > 0 {
			rv = append(rv, attr)
		}
	}
	return rv
}

func (s groupMembershipState) values(attr string) []string {
	switch attr {
	case attrGroupMember:
		return s.member
	case attrGroupUniqueMember:
		return s.uniqueMember
	case attrGroupMemberPosix:
		return s.memberUID
	}
	return nil
}

func sortedByDocumentedOrder(attrs []string) []string {
	rv := make([]string, 0, len(attrs))
	for _, attr := range documentedOrder {
		if slices.Contains(attrs, attr) {
			rv = append(rv, attr)
		}
	}
	return rv
}

// membershipAttemptMode says how a grant's targets are to be used.
type membershipAttemptMode int

const (
	// attemptCandidates: the targets are ordered guesses (the inferred order), or
	// the operator's pin. The first target the server accepts and the post-read
	// confirms wins, and a schema rejection of one is the signal to try the next.
	attemptCandidates membershipAttemptMode = iota
	// attemptEveryTarget: the targets are the attributes the entry itself shows
	// holding membership, so every one of them is written and confirmed. A
	// rejection is reported rather than skipped: skipping it would return success
	// while one of the entry's two consumer views stayed un-maintained, which is
	// the whole reason for following the entry's content instead of a fixed rule.
	attemptEveryTarget
)

// grantTargets returns the attributes a grant is attempted on, and how.
//
// A pin replaces the decision entirely for a grant: it is the attribute the
// operator chose, so nothing else is written. With a single target a rejection
// is fatal by construction -- there is no next candidate to fall through to,
// which is exactly what "never fall through" means for a pin.
func (p groupMembershipPlan) grantTargets(pinned string) ([]string, membershipAttemptMode) {
	if pinned != "" {
		return []string{pinned}, attemptCandidates
	}
	if p.inferred {
		return p.targets, attemptCandidates
	}
	return p.targets, attemptEveryTarget
}

// pinnedMemberAttribute returns the attribute the operator pinned, or "" when the
// attribute is learned per entry. An unset field and an explicit "auto" are the
// same thing.
func pinnedMemberAttribute(configured string) string {
	if configured == "" || strings.EqualFold(configured, config.GroupMemberAttributeAuto) {
		return ""
	}
	return configured
}

// principalIdentity is what the membership matcher knows about the principal: its
// canonical DN, plus the login names a memberUid value can take for it.
//
// The names matter because memberUid holds a login name, not a DN, and both the
// uid and the cn form are in service: findMember resolves a stored memberUid by
// uid and then by cn, so a directory may have written either one.
type principalIdentity struct {
	// dn is the principal's canonicalized DN, which is what the read path reports
	// for a DN-valued membership.
	dn string
	// uid and cn are the principal entry's own attributes. Either is empty when
	// the entry does not carry it, or when the entry could not be read at all.
	uid string
	cn  string
	// rdn is the value of the principal DN's first RDN, which is the form the
	// previous implementation wrote unconditionally.
	rdn string
}

// names returns every login name the principal can be stored as, most specific
// first, deduplicated case-insensitively.
func (id principalIdentity) names() []string {
	seen := make(map[string]bool, 3)
	var rv []string
	for _, name := range []string{id.uid, id.cn, id.rdn} {
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		rv = append(rv, name)
	}
	return rv
}

// holdsName reports whether a stored memberUid value names the principal.
func (id principalIdentity) holdsName(value string) bool {
	return slices.ContainsFunc(id.names(), func(name string) bool {
		return strings.EqualFold(name, value)
	})
}

// principalIdentity resolves the principal's identity, reading its entry when the
// DN alone does not give its uid and cn.
//
// The read costs one base-scoped search, cached per principal DN for the lifetime
// of the sync, and it is what makes a memberUid membership written as the uid
// visible when the principal is named by cn -- without it, such a membership
// would look absent, and a revoke would report success while leaving the member.
//
// A principal that cannot be found is not an error: an entry the connector cannot
// read cannot be resolved by the read path either, so the DN's own RDN value is
// all there is. Any other failure is returned, because guessing here means
// reporting a membership as absent when it may not be.
func (g *groupResourceType) principalIdentity(ctx context.Context, principalDN *ldap3.DN) (principalIdentity, error) {
	id := principalIdentity{dn: principalDN.String()}
	if len(principalDN.RDNs) > 0 && len(principalDN.RDNs[0].Attributes) > 0 {
		id.rdn = strings.TrimSpace(principalDN.RDNs[0].Attributes[0].Value)
	}

	g.principalNamesMtx.Lock()
	cached, ok := g.principalNamesCache[id.dn]
	g.principalNamesMtx.Unlock()
	if ok {
		id.uid, id.cn = cached.uid, cached.cn
		return id, nil
	}

	entry, err := g.client.LdapGet(ctx, principalDN, "", []string{attrUserUID, attrUserCommonName})
	switch {
	case err == nil:
		id.uid = entry.GetEqualFoldAttributeValue(attrUserUID)
		id.cn = entry.GetEqualFoldAttributeValue(attrUserCommonName)
	case ldap3.IsErrorAnyOf(err, ldap3.LDAPResultNoSuchObject) || status.Code(err) == codes.NotFound:
		// Unreadable under the connector's user filter. The read path cannot
		// resolve a membership to it either, so the RDN value is the whole answer.
	default:
		return principalIdentity{}, fmt.Errorf("ldap-connector: failed to read group member %q: %w", id.dn, err)
	}

	g.principalNamesMtx.Lock()
	if g.principalNamesCache == nil {
		g.principalNamesCache = make(map[string]principalNameForms)
	}
	g.principalNamesCache[id.dn] = principalNameForms{uid: id.uid, cn: id.cn}
	g.principalNamesMtx.Unlock()

	return id, nil
}

// principalNameForms is the cached subset of a principalIdentity that costs a
// search to learn.
type principalNameForms struct {
	uid string
	cn  string
}

// matchPrincipal reports, per membership attribute, the exact stored values that
// name the principal. A nil answer means the principal is in none of them.
//
// Only this group's own stored values are examined: an inherited membership must
// not look like a direct one, or a grant would report success off the back of
// another group's membership and a revoke would remove the wrong thing.
// principalMatchResolver resolves a stored login-name value to the DN the read
// path reports for it, and returns an empty string when nothing resolves. It is
// findMember in production; tests pass a stub.
type principalMatchResolver func(ctx context.Context, value string) (string, error)

// matchPrincipal reports, per membership attribute, the exact stored values that
// name the principal. A nil answer means the principal is in none of them.
//
// Only this group's own stored values are examined: an inherited membership must
// not look like a direct one, or a grant would report success off the back of
// another group's membership and a revoke would remove the wrong thing.
//
// A DN-valued match is exact: the value canonicalizes to the principal's DN. A
// name-valued match (memberUid, or a bare name in a DN-valued attribute) is only a
// candidate until resolve confirms it, because findMember resolves a stored value
// by uid and then by cn -- so a value that is one of the principal's own names can
// still belong to another entry, a user whose uid equals this principal's cn. The
// confirmation is what keeps a revoke from deleting that other user's membership.
func matchPrincipal(ctx context.Context, entry *ldap3.Entry, id principalIdentity, resolve principalMatchResolver) (map[string][]string, error) {
	var rv map[string][]string
	add := func(attr, value string) {
		if rv == nil {
			rv = make(map[string][]string, len(membershipAttrs))
		}
		rv[attr] = append(rv[attr], value)
	}

	confirm := func(value string) (bool, error) {
		memberDN, err := resolve(ctx, value)
		if err != nil {
			return false, err
		}
		return strings.EqualFold(memberDN, id.dn), nil
	}

	for _, attr := range []string{attrGroupMember, attrGroupUniqueMember} {
		for _, value := range entry.GetEqualFoldAttributeValues(attr) {
			parsed, err := ldap.CanonicalizeDN(value)
			if err == nil {
				// Attribute types in a DN are case-insensitive, and CanonicalizeDN
				// lowercases values only for the types in caseInsensitiveAttrs, so
				// the comparison is case-insensitive on top of canonicalization.
				if strings.EqualFold(parsed.String(), id.dn) {
					add(attr, value)
				}
				continue
			}
			// A value that is not a DN is resolved as a login name by the read
			// path (the same findMember fallback memberUid uses), so a bare name
			// stored in a DN-valued attribute can still name the principal.
			if !id.holdsName(value) {
				continue
			}
			ok, err := confirm(value)
			if err != nil {
				return nil, err
			}
			if ok {
				add(attr, value)
			}
		}
	}

	for _, value := range entry.GetEqualFoldAttributeValues(attrGroupMemberPosix) {
		if !id.holdsName(value) {
			continue
		}
		ok, err := confirm(value)
		if err != nil {
			return nil, err
		}
		if ok {
			add(attrGroupMemberPosix, value)
		}
	}

	return rv, nil
}

// resolveMemberName is the production resolver: the read path's own lookup of a
// stored login name, uid first and then cn.
func (g *groupResourceType) resolveMemberName(ctx context.Context, value string) (string, error) {
	return g.findMember(ctx, value)
}

// membershipState builds the decision input from the group entry and the
// principal's identity, confirming every name-valued candidate through resolve.
func membershipState(ctx context.Context, entry *ldap3.Entry, id principalIdentity, resolve principalMatchResolver) (groupMembershipState, error) {
	matches, err := matchPrincipal(ctx, entry, id, resolve)
	if err != nil {
		return groupMembershipState{}, err
	}

	attrs := make([]string, 0, len(matches))
	for attr := range matches {
		attrs = append(attrs, attr)
	}

	return groupMembershipState{
		// Equal-fold, unlike the read path's own objectClass read: a server that
		// returns the attribute name in another case must not silently cost the
		// decision its objectClass evidence, which is the only thing that orders
		// the candidates for an entry holding no membership.
		objectClasses:   entry.GetEqualFoldAttributeValues("objectClass"),
		member:          entry.GetEqualFoldAttributeValues(attrGroupMember),
		uniqueMember:    entry.GetEqualFoldAttributeValues(attrGroupUniqueMember),
		memberUID:       entry.GetEqualFoldAttributeValues(attrGroupMemberPosix),
		principalIn:     sortedByDocumentedOrder(attrs),
		principalValues: matches,
	}, nil
}

// memberUIDValue returns the memberUid value to write for the principal.
//
// The entry decides the form. memberUid holds a login name and a directory may
// store either the uid or the cn (findMember resolves both), so the connector
// writes the form this group's own values already use: writing the other one
// would leave a membership the group's own readers do not see. uid is preferred
// when neither form is in evidence, and the first RDN value -- what the previous
// implementation wrote unconditionally -- is the last resort.
func memberUIDValue(entry *ldap3.Entry, id principalIdentity) string {
	stored := entry.GetEqualFoldAttributeValues(attrGroupMemberPosix)
	if id.uid != "" && containsFold(stored, id.uid) {
		return id.uid
	}
	if id.cn != "" && containsFold(stored, id.cn) {
		return id.cn
	}
	if id.uid != "" {
		return id.uid
	}
	return id.rdn
}

func containsFold(values []string, want string) bool {
	return slices.ContainsFunc(values, func(value string) bool {
		return strings.EqualFold(value, want)
	})
}

// membershipValue returns the values to add for one attribute.
func membershipValue(entry *ldap3.Entry, id principalIdentity, attr string) ([]string, error) {
	switch attr {
	case attrGroupMember, attrGroupUniqueMember:
		return []string{id.dn}, nil
	case attrGroupMemberPosix:
		value := memberUIDValue(entry, id)
		if value == "" {
			return nil, fmt.Errorf("ldap-connector: cannot determine a memberUid value for %q", id.dn)
		}
		return []string{value}, nil
	default:
		return nil, fmt.Errorf("ldap-connector: %q is not a group membership attribute this connector writes", attr)
	}
}

// membershipDeletion names one membership attribute and the exact stored values to
// remove from it.
type membershipDeletion struct {
	attr   string
	values []string
}

// membershipEffects are the two effects the write loops perform. Both are
// injected so every failure mode of the loops is unit-testable without a
// directory: the loop is where a mistake would hide, and it cannot be exercised
// locally without a container runtime.
type membershipEffects struct {
	// value returns the values to add for attr.
	value func(ctx context.Context, attr string) ([]string, error)
	// add adds values to one attribute and reports whether a read taken on the
	// same connection showed the membership. A non-nil error is the server's own
	// result for that request, nothing swallowed.
	add func(ctx context.Context, attr string, values []string) (bool, error)
	// remove deletes the exact stored values from every named attribute in ONE
	// request and reports whether a read taken on the same connection showed the
	// membership gone.
	remove func(ctx context.Context, deletions []membershipDeletion) (bool, error)
}

// groupEffects wires the loops to the directory.
//
// The confirming read runs on the connection that accepted the write, and it asks
// the read path's own question: would a sync of this group show this principal?
func (g *groupResourceType) groupEffects(ctx context.Context, l *zap.Logger, groupDN string, group *ldap3.Entry, id principalIdentity) membershipEffects {
	holds := func(entry *ldap3.Entry) (bool, error) {
		return g.groupHoldsPrincipal(ctx, l, entry, id)
	}
	absent := func(entry *ldap3.Entry) (bool, error) {
		held, err := g.groupHoldsPrincipal(ctx, l, entry, id)
		return !held, err
	}

	return membershipEffects{
		value: func(_ context.Context, attr string) ([]string, error) {
			return membershipValue(group, id, attr)
		},
		add: func(ctx context.Context, attr string, values []string) (bool, error) {
			req := ldap3.NewModifyRequest(groupDN, nil)
			req.Add(attr, values)
			return g.client.LdapModifyStrictAndConfirm(ctx, req, membershipAttrs, holds)
		},
		remove: func(ctx context.Context, deletions []membershipDeletion) (bool, error) {
			req := ldap3.NewModifyRequest(groupDN, nil)
			for _, deletion := range deletions {
				req.Delete(deletion.attr, deletion.values)
			}
			return g.client.LdapModifyStrictAndConfirm(ctx, req, membershipAttrs, absent)
		},
	}
}

// groupHoldsPrincipal reports whether the read path would report id.dn as a
// direct member of this group. It is the post-condition check, and it asks
// "would a sync see this membership?" rather than "did the server return
// success?".
//
// The resolution is the read path's own: a stored value that parses as a DN
// resolves to that DN, and one that does not is resolved through findMember's
// uid-then-cn search. The two pre-filters make that affordable on a large group,
// and each skips only values that cannot change the answer: a DN-valued membership
// that canonicalizes to something else cannot resolve to the principal (the read
// path's lookup of that same DN returns that DN), and a memberUid value that is
// not one of the principal's own login names cannot resolve to it either
// (findMember resolves by uid or cn, so a value that resolves to the principal is
// one of those names).
//
// A plain DN string comparison is deliberately not the check: CanonicalizeDN
// lowercases values only for the attribute types in caseInsensitiveAttrs, so the
// read path is the authority here, not our string handling.
func (g *groupResourceType) groupHoldsPrincipal(ctx context.Context, l *zap.Logger, entry *ldap3.Entry, id principalIdentity) (bool, error) {
	for _, attr := range membershipAttrs {
		for _, value := range entry.GetEqualFoldAttributeValues(attr) {
			if parsed, err := ldap.CanonicalizeDN(value); err == nil {
				if strings.EqualFold(parsed.String(), id.dn) {
					return true, nil
				}
				continue
			}
			if !id.holdsName(value) {
				continue
			}
			memberDN, err := g.resolveMemberName(ctx, value)
			if err != nil {
				return false, err
			}
			if strings.EqualFold(memberDN, id.dn) {
				return true, nil
			}
		}
	}

	l.Debug("baton-ldap: group does not hold the principal",
		zap.String("group_dn", entry.DN), zap.String("principal_dn", id.dn))

	return false, nil
}

// retryableMembershipError marks an outcome the connector could not establish as
// retryable. Only codes.Unavailable and codes.DeadlineExceeded are retried by the
// SDK's provisioner (retry/retry.go), so an ambiguous write has to be reported
// that way rather than as a plain error, which would fail the task instead of
// re-running it.
func retryableMembershipError(format string, args ...any) error {
	return status.Errorf(codes.Unavailable, "baton-ldap: "+format, args...)
}

// isMembershipSchemaRejection reports whether err is the server refusing the
// membership attribute itself. That is the one rejection a candidate loop may
// learn from: 65 objectClassViolation means the entry's classes do not permit the
// attribute, and 17 undefinedAttributeType means the server has no such attribute
// type at all. A value problem is a different failure (21 invalidAttributeSyntax,
// 19 constraintViolation) and must not be mistaken for it.
func isMembershipSchemaRejection(err error) bool {
	return ldap3.IsErrorAnyOf(err,
		ldap3.LDAPResultObjectClassViolation,
		ldap3.LDAPResultUndefinedAttributeType)
}

// isAlreadyPresent reports the server's "the value is already there" answer: 20
// attributeOrValueExists, or 68 entryAlreadyExists, which some servers return
// where the other does not.
func isAlreadyPresent(err error) bool {
	return ldap3.IsErrorAnyOf(err,
		ldap3.LDAPResultAttributeOrValueExists,
		ldap3.LDAPResultEntryAlreadyExists)
}

// grantMembership writes the principal's membership into the plan's targets.
//
// One attribute per request is deliberate: an Add naming two attributes is rolled
// back as a whole when either value already exists (RFC 4511 4.6), so a batched
// grant would fail on a group that already holds the principal in one of them.
// The duplicate is also why a 20 is answered with the already-exists annotation
// instead of an error -- the post-condition -- membership -- holds either way.
//
// A write the server accepted but the post-read did not confirm is reported as
// retryable and deliberately NOT advanced past: the one thing that must not
// happen there is a second attribute being written, which would leave the
// principal in two places on a directory that needed only one.
func grantMembership(
	ctx context.Context,
	l *zap.Logger,
	targets []string,
	mode membershipAttemptMode,
	effects membershipEffects,
) (annotations.Annotations, error) {
	attempted := make([]string, 0, len(targets))
	written := make([]string, 0, len(targets))
	var lastRejection error

	for _, attr := range targets {
		attempted = append(attempted, attr)

		values, err := effects.value(ctx, attr)
		if err != nil {
			return nil, err
		}

		confirmed, err := effects.add(ctx, attr, values)
		switch {
		case err == nil && confirmed:
			l.Info("baton-ldap: granted group membership",
				zap.String("attribute", attr), zap.Strings("values", values))
			written = append(written, attr)
			if mode == attemptCandidates {
				return nil, nil
			}

		case err == nil:
			return nil, retryableMembershipError(
				"the group accepted a write of %s but does not show the membership yet", attr)

		case isAlreadyPresent(err):
			l.Debug("baton-ldap: membership value is already present", zap.String("attribute", attr))
			if mode == attemptCandidates {
				return annotations.New(&v2.GrantAlreadyExists{}), nil
			}

		case isMembershipSchemaRejection(err):
			l.Info("baton-ldap: the group does not permit this membership attribute",
				zap.String("attribute", attr), zap.Error(err))
			if mode == attemptEveryTarget {
				return nil, fmt.Errorf("the entry does not permit %s (already wrote %v): %w", attr, written, err)
			}
			lastRejection = err

		default:
			return nil, err
		}
	}

	if len(written) > 0 {
		return nil, nil
	}
	if lastRejection != nil {
		return nil, fmt.Errorf("no candidate attribute was accepted (attempted %v): %w", attempted, lastRejection)
	}

	// Every target already held the principal's value.
	return annotations.New(&v2.GrantAlreadyExists{}), nil
}

// revokeDeletions pairs each attribute that holds the principal with the exact
// stored values that matched it.
//
// One request naming all of them is sound precisely because every value included
// is present: RFC 4511 4.6 makes the list atomic, and a value that is genuinely
// absent would fail the whole request with 16. That is why the values are the
// stored strings and not a normalized form of them.
func revokeDeletions(plan groupMembershipPlan, values map[string][]string) []membershipDeletion {
	deletions := make([]membershipDeletion, 0, len(plan.targets))
	for _, attr := range plan.targets {
		if len(values[attr]) == 0 {
			continue
		}
		deletions = append(deletions, membershipDeletion{attr: attr, values: values[attr]})
	}
	return deletions
}

// revokeMembership performs the single atomic delete.
//
// stale reports the one answer the caller handles differently: the server said
// the value is not there (16 noSuchAttribute), which means the read this delete
// was decided from is out of date. Erroring out on that would be wrong (the
// membership may already be gone) and reporting success would be wrong too (it
// may have moved), so the caller re-reads and decides from the new state.
func revokeMembership(ctx context.Context, l *zap.Logger, deletions []membershipDeletion, effects membershipEffects) (bool, error) {
	removed, err := effects.remove(ctx, deletions)
	switch {
	case err == nil && removed:
		l.Info("baton-ldap: revoked group membership",
			zap.Int("attributes", len(deletions)))
		return false, nil

	case err == nil:
		return false, retryableMembershipError(
			"the group accepted the delete but still shows the membership")

	case ldap3.IsErrorAnyOf(err, ldap3.LDAPResultNoSuchAttribute):
		l.Info("baton-ldap: a membership value to delete was not present", zap.Error(err))
		return true, nil

	default:
		return false, err
	}
}

// revokeAbsence is what an absent direct membership turned out to be.
type revokeAbsence struct {
	// primaryGroup is true when the membership the read path reports comes from
	// the principal's own gidNumber rather than from any membership attribute.
	primaryGroup bool
	// inheritedVia names the source of an inherited membership, empty when the
	// membership is not inherited.
	inheritedVia string
	// truncated is true when the nested-group search stopped at one of its bounds
	// -- the depth cap or the total-lookup cap -- without finding the principal, so
	// "not inherited" is not established.
	truncated bool
}

// decideRevokeAbsence renders the outcome for a membership the read path reports
// but no membership attribute holds. It is pure, so the precedence between the
// two guards is testable without a directory.
//
// Neither guard may answer "already revoked": both describe a membership that
// exists and that C1 will report again on the next sync, and a success here would
// be the silent failure this change exists to remove.
func decideRevokeAbsence(absence revokeAbsence, groupDN string, principalDN string) (annotations.Annotations, error) {
	switch {
	case absence.primaryGroup:
		return nil, fmt.Errorf(
			"baton-ldap: cannot revoke %q from group %q: the membership is the user's primary group (gidNumber), "+
				"so change the user's gidNumber instead", principalDN, groupDN)

	case absence.inheritedVia != "":
		return nil, fmt.Errorf(
			"baton-ldap: cannot revoke %q from group %q: the membership is inherited via %s, "+
				"so revoke the membership of the source instead", principalDN, groupDN, absence.inheritedVia)

	case absence.truncated:
		return nil, fmt.Errorf(
			"baton-ldap: cannot revoke %q from group %q: no direct membership was found, and the nested-group search "+
				"stopped early (after %d levels or %d entries) without establishing that there is none",
			principalDN, groupDN, inheritedMembershipDepth, inheritedMembershipLookupCap)
	}

	return annotations.New(&v2.GrantAlreadyRevoked{}), nil
}

// primaryGroupMember reports whether this group is the principal's primary group,
// in which case the membership is a property of the user entry and no membership
// write can remove it.
//
// The check mirrors the read path's own primary-group expansion: a base-scoped
// search on the principal with the group's gidNumber, so "C1 reports this
// membership" and "this connector can revoke it" cannot disagree.
func (g *groupResourceType) primaryGroupMember(ctx context.Context, group *ldap3.Entry, principalDN *ldap3.DN) (bool, error) {
	gid := group.GetEqualFoldAttributeValue(attrGroupIdPosix)
	if gid == "" {
		return false, nil
	}

	entries, _, err := g.client.LdapSearch(
		ctx,
		ldap3.ScopeBaseObject,
		principalDN,
		fmt.Sprintf(groupMemberGidNumber, ldap3.EscapeFilter(gid)),
		[]string{"dn"},
		"",
		1,
	)
	if err != nil {
		if ldap3.IsErrorAnyOf(err, ldap3.LDAPResultNoSuchObject) || status.Code(err) == codes.NotFound {
			return false, nil
		}
		return false, fmt.Errorf("ldap-connector: failed to check the primary group of %q: %w", principalDN.String(), err)
	}

	return len(entries) > 0, nil
}

// inheritedMembershipDepth bounds the nested-group traversal. A chain deeper than
// this reports that it was cut short rather than answering "not inherited", so a
// depth-capped search can never produce a false "already revoked".
const inheritedMembershipDepth = 5

// inheritedMembershipLookupCap bounds how many entries the traversal reads in
// total. Most of a group's member values are users, and each one costs a lookup
// that comes back "not a group", so without a cap a revoke of an already-removed
// member on a very large group would spend one search per member. Hitting the cap
// is reported the same way as the depth cap, never as "not inherited".
const inheritedMembershipLookupCap = 50

// inheritedSourceFromGrant reads the received grant's Sources.
//
// The SDK's expander builds an expanded grant with the *user* as principal and the
// contributing entitlements in Sources, each flagged direct or not, so a
// membership this group only appears to hold through a nested group arrives with a
// source that is not direct on this group's own entitlement. An empty answer means
// "not inherited, or the caller forwarded no sources" -- whether C1 forwards them
// on Revoke is not established, which is why the traversal exists alongside it.
func inheritedSourceFromGrant(gr *v2.Grant) string {
	sources := gr.GetSources().GetSources()
	if len(sources) == 0 {
		return ""
	}

	own := gr.GetEntitlement().GetId()
	if source, ok := sources[own]; ok && source.GetIsDirect() {
		return ""
	}

	indirect := make([]string, 0, len(sources))
	for entitlementID, source := range sources {
		if entitlementID == own || source.GetIsDirect() {
			continue
		}
		indirect = append(indirect, entitlementID)
	}
	if len(indirect) == 0 {
		// The grant names only this group's own entitlement and it is not marked
		// direct, so there is no other entitlement to name.
		return own
	}

	sort.Strings(indirect)

	return indirect[0]
}

// inheritedVia names where an inherited membership comes from, first from the
// grant's own Sources and then, if those say nothing, by walking this group's
// group-valued members.
func (g *groupResourceType) inheritedVia(ctx context.Context, l *zap.Logger, groupDN string, id principalIdentity, gr *v2.Grant) (string, bool, error) {
	if source := inheritedSourceFromGrant(gr); source != "" {
		return source, false, nil
	}

	return g.inheritedViaTraversal(ctx, l, groupDN, id)
}

// inheritedViaTraversal walks group-valued members of groupDN, recursively and
// within a depth cap, and returns the DN of the group that holds the principal
// directly. truncated reports that the walk stopped at the cap, which is not the
// same answer as "not found".
//
// This is the guard for a membership the read path reports through expansion: a
// member value that resolves to a group produces a grant on the parent
// entitlement with the user as principal, which reaches Revoke as an ordinary
// user grant for a membership that exists in no attribute of this group.
func (g *groupResourceType) inheritedViaTraversal(ctx context.Context, l *zap.Logger, groupDN string, id principalIdentity) (string, bool, error) {
	visited := make(map[string]bool)
	truncated := false
	lookups := 0

	var walk func(dn string, depth int) (string, error)
	walk = func(dn string, depth int) (string, error) {
		if visited[dn] {
			return "", nil
		}
		if depth > inheritedMembershipDepth || lookups >= inheritedMembershipLookupCap {
			truncated = true
			return "", nil
		}
		visited[dn] = true
		lookups++

		entry, err := g.getGroup(ctx, dn)
		if err != nil {
			if isNotFound(err) {
				// A member that is not a group this connector can read is not a
				// nested group as far as this connector is concerned.
				return "", nil
			}
			return "", err
		}

		for _, value := range valuesOf(entry, membershipAttrs) {
			parsed, err := ldap.CanonicalizeDN(value)
			if err != nil {
				continue
			}
			memberDN := parsed.String()
			if memberDN == "" || memberDN == dn {
				continue
			}

			if lookups >= inheritedMembershipLookupCap {
				truncated = true
				return "", nil
			}
			member, err := g.getGroup(ctx, memberDN)
			if err != nil {
				if isNotFound(err) {
					continue
				}
				return "", err
			}
			lookups++

			holds, err := g.groupHoldsPrincipal(ctx, l, member, id)
			if err != nil {
				return "", err
			}
			if holds {
				return memberDN, nil
			}

			found, err := walk(memberDN, depth+1)
			if err != nil {
				return "", err
			}
			if found != "" {
				return found, nil
			}
		}

		return "", nil
	}

	// The first walk covers this group's own direct members.
	found, err := walk(groupDN, 1)
	if err != nil {
		return "", false, err
	}

	return found, truncated, nil
}

// valuesOf returns the values of every named attribute on an entry.
func valuesOf(entry *ldap3.Entry, attrs []string) []string {
	var rv []string
	for _, attr := range attrs {
		rv = append(rv, entry.GetEqualFoldAttributeValues(attr)...)
	}
	return rv
}

// isNotFound reports whether err means "no such entry". LdapGet wraps the
// server's noSuchObject in codes.NotFound, and a caller-supplied DN can raise
// either.
func isNotFound(err error) bool {
	return ldap3.IsErrorAnyOf(err, ldap3.LDAPResultNoSuchObject) || status.Code(err) == codes.NotFound
}

// revokeAbsentMembership decides what to do when no membership attribute of the
// group holds the principal: the primary-group guard, then the inherited-
// membership guard, then already-revoked.
func (g *groupResourceType) revokeAbsentMembership(
	ctx context.Context,
	l *zap.Logger,
	groupDN string,
	group *ldap3.Entry,
	principalDN *ldap3.DN,
	id principalIdentity,
	gr *v2.Grant,
) (annotations.Annotations, error) {
	primary, err := g.primaryGroupMember(ctx, group, principalDN)
	if err != nil {
		return nil, err
	}

	var source string
	var truncated bool
	if !primary {
		source, truncated, err = g.inheritedVia(ctx, l, groupDN, id, gr)
		if err != nil {
			return nil, err
		}
	}

	return decideRevokeAbsence(
		revokeAbsence{primaryGroup: primary, inheritedVia: source, truncated: truncated},
		groupDN, id.dn)
}

// Grant adds the principal to the group.
func (g *groupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != resourceTypeUser.Id {
		return nil, fmt.Errorf("baton-ldap: only users can have group membership granted")
	}

	groupDN := entitlement.Resource.Id.Resource

	group, err := g.getGroup(ctx, groupDN)
	if err != nil {
		return nil, err
	}

	principalDN, err := ldap.CanonicalizeDN(principal.Id.Resource)
	if err != nil {
		return nil, err
	}

	id, err := g.principalIdentity(ctx, principalDN)
	if err != nil {
		return nil, err
	}

	state, err := membershipState(ctx, group, id, g.resolveMemberName)
	if err != nil {
		return nil, err
	}
	plan := planGroupMembership(state)

	if plan.dynamic {
		return nil, fmt.Errorf("baton-ldap: cannot grant membership in dynamic groupOfURLs group %q directly", groupDN)
	}
	if plan.present {
		l.Info("baton-ldap: group membership is already present",
			zap.String("group_dn", groupDN), zap.String("principal_dn", id.dn),
			zap.Strings("attributes", plan.targets))
		return annotations.New(&v2.GrantAlreadyExists{}), nil
	}

	pinned := pinnedMemberAttribute(g.groupMemberAttribute)
	if pinned != "" {
		l.Info("baton-ldap: group membership attribute is pinned",
			zap.String("group_dn", groupDN), zap.String("attribute", pinned))
	}
	if plan.inferred {
		l.Info("baton-ldap: the group entry shows no membership; trying candidate attributes in order",
			zap.String("group_dn", groupDN), zap.Strings("candidates", plan.targets))
	}

	targets, mode := plan.grantTargets(pinned)

	annos, err := grantMembership(ctx, l, targets, mode, g.groupEffects(ctx, l, groupDN, group, id))
	if err != nil {
		return nil, fmt.Errorf(
			"ldap-connector: failed to grant group membership in %q (objectClass %v): %w",
			groupDN, state.objectClasses, err)
	}

	return annos, nil
}

// Revoke removes the principal from the group.
//
// It acts on where the membership actually is, never on a pinned attribute or on a
// guess: deleting from an attribute that does not hold the value is the silent
// failure this change exists to remove. A pin therefore governs grants only.
func (g *groupResourceType) Revoke(ctx context.Context, gr *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	entitlement := gr.Entitlement
	principal := gr.Principal

	if principal.Id.ResourceType != resourceTypeUser.Id {
		return nil, fmt.Errorf("baton-ldap: only users can have group membership revoked")
	}

	groupDN := entitlement.Resource.Id.Resource

	group, err := g.getGroup(ctx, groupDN)
	if err != nil {
		return nil, err
	}

	principalDN, err := ldap.CanonicalizeDN(principal.Id.Resource)
	if err != nil {
		return nil, err
	}

	id, err := g.principalIdentity(ctx, principalDN)
	if err != nil {
		return nil, err
	}

	state, err := membershipState(ctx, group, id, g.resolveMemberName)
	if err != nil {
		return nil, err
	}
	plan := planGroupMembership(state)

	if plan.dynamic {
		return nil, fmt.Errorf("baton-ldap: cannot revoke membership in dynamic groupOfURLs group %q directly", groupDN)
	}

	if !plan.present {
		return g.revokeAbsentMembership(ctx, l, groupDN, group, principalDN, id, gr)
	}

	deletions := revokeDeletions(plan, state.principalValues)
	stale, err := revokeMembership(ctx, l, deletions, g.groupEffects(ctx, l, groupDN, group, id))
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: failed to revoke group membership in %q: %w", groupDN, err)
	}
	if !stale {
		return nil, nil
	}

	// The delete found nothing there: the read it was decided from is out of
	// date, or something removed the value first. Re-read and answer from the
	// state now, which is the only honest basis for either outcome.
	fresh, err := g.getGroup(ctx, groupDN)
	if err != nil {
		if isNotFound(err) {
			// The group itself is gone, so there is nothing left to revoke.
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, err
	}
	freshState, err := membershipState(ctx, fresh, id, g.resolveMemberName)
	if err != nil {
		return nil, err
	}
	if planGroupMembership(freshState).present {
		return nil, retryableMembershipError(
			"the membership of %q in %q is still present after the delete reported it absent", id.dn, groupDN)
	}

	return g.revokeAbsentMembership(ctx, l, groupDN, fresh, principalDN, id, gr)
}
