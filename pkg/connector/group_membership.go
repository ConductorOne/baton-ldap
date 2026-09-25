package connector

import (
	"context"
	"fmt"
	"slices"
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
	// (A rejection after an earlier target was written leaves the entry partly
	// written; see the note in grantMembership.)
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
// canonical DN, the login names its entry carries, and the subset of those names
// that the read path's own resolution actually maps to it.
//
// The resolved names are what makes a membership write safe. memberUid holds a
// login name, not a DN, and both the uid and the cn form are in service, so the
// connector writes a name -- and a name it writes must be one the read path will
// resolve back to this principal. A name that resolves to a different entry is a
// name that either cannot be added (the value is already there, as that entry's)
// or would store a membership sync cannot see.
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
	// resolvedNames are the principal's login names that findMember maps to this
	// principal, most specific first: the uid when it resolves, then the cn, then
	// the first RDN value. A name that resolves to another entry is not here.
	resolvedNames []string
}

// nameCandidates returns every login name the principal could be stored as,
// deduplicated case-insensitively, uid first: the order the read path resolves in.
func (id principalIdentity) nameCandidates() []string {
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

// resolvesName reports whether a stored login-name value resolves to this
// principal. It is deliberately not a string comparison against the names the
// entry carries: findMember resolves a name by uid first and cn second, so a value
// equal to this principal's cn can belong to another entry whose uid it also is.
func (id principalIdentity) resolvesName(value string) bool {
	return slices.ContainsFunc(id.resolvedNames, func(name string) bool {
		return strings.EqualFold(name, value)
	})
}

// principalIdentity resolves the principal's identity, reading its entry for the
// uid and cn the DN alone cannot give, and asking the read path's own resolution
// which of the principal's names map back to it.
//
// The resolution is done fresh on every call rather than cached: a connector in
// service mode runs for weeks, and a name re-pointed at another entry must change
// the next write, not the one after a restart. It costs at most one search per
// distinct name (uid, cn, and the first RDN value, usually two of them).
//
// A principal that cannot be found is not an error: an entry the connector cannot
// read cannot be resolved by the read path either, so its names resolve to nothing
// and a DN-valued membership is the only form that can be written for it. Any
// other failure is returned, because guessing here means writing a membership the
// read path will not see.
func (g *groupResourceType) principalIdentity(ctx context.Context, principalDN *ldap3.DN) (principalIdentity, error) {
	id := principalIdentity{dn: principalDN.String()}
	if len(principalDN.RDNs) > 0 && len(principalDN.RDNs[0].Attributes) > 0 {
		id.rdn = strings.TrimSpace(principalDN.RDNs[0].Attributes[0].Value)
	}

	entry, err := g.client.LdapGet(ctx, principalDN, "", []string{attrUserUID, attrUserCommonName})
	switch {
	case err == nil:
		id.uid = entry.GetEqualFoldAttributeValue(attrUserUID)
		id.cn = entry.GetEqualFoldAttributeValue(attrUserCommonName)
	case isNotFound(err):
		// Unreadable under the connector's user filter. The read path cannot
		// resolve a membership to it either, so no name resolves.
	default:
		return principalIdentity{}, fmt.Errorf("ldap-connector: failed to read group member %q: %w", id.dn, err)
	}

	for _, candidate := range id.nameCandidates() {
		memberDN, err := g.lookupMember(ctx, candidate)
		if err != nil {
			return principalIdentity{}, fmt.Errorf("ldap-connector: failed to resolve the group member name %q: %w", candidate, err)
		}
		if strings.EqualFold(memberDN, id.dn) {
			id.resolvedNames = append(id.resolvedNames, candidate)
		}
	}

	return id, nil
}

// matchPrincipal reports, per membership attribute, the exact stored values that
// name the principal. A nil answer means the principal is in none of them.
//
// Only this group's own stored values are examined: an inherited membership must
// not look like a direct one, or a grant would report success off the back of
// another group's membership and a revoke would remove the wrong thing.
//
// A DN-valued value is exact: it canonicalizes to the principal's DN. A
// login-name value counts only when the read path resolves it to the principal
// (resolvesName), which is what keeps a value that belongs to another entry -- a
// user whose uid is this principal's cn -- out of both a grant and a revoke.
func matchPrincipal(entry *ldap3.Entry, id principalIdentity) map[string][]string {
	var rv map[string][]string
	add := func(attr, value string) {
		if rv == nil {
			rv = make(map[string][]string, len(membershipAttrs))
		}
		rv[attr] = append(rv[attr], value)
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
			if id.resolvesName(value) {
				add(attr, value)
			}
		}
	}

	for _, value := range entry.GetEqualFoldAttributeValues(attrGroupMemberPosix) {
		if id.resolvesName(value) {
			add(attrGroupMemberPosix, value)
		}
	}

	return rv
}

// membershipState builds the decision input from the group entry and the
// principal's identity. It performs no I/O.
func membershipState(entry *ldap3.Entry, id principalIdentity) groupMembershipState {
	matches := matchPrincipal(entry, id)
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
	}
}

// memberUIDValue returns the memberUid value to write for the principal, or the
// empty string when the principal has no name the read path resolves to it.
//
// Only resolved names are usable. The entry decides the form -- a directory may
// store either the uid or the cn, and writing the form this group does not use
// would leave a membership its own readers miss -- but a name the entry already
// holds is not usable when it resolves to a different entry: adding it returns 20
// (the value is that other user's) and storing anything else would be invisible to
// sync. So the entry's forms are considered first, and only among the names that
// resolve to this principal; otherwise the uid (the first resolved name), and
// nothing at all if none resolves.
func memberUIDValue(entry *ldap3.Entry, id principalIdentity) string {
	stored := entry.GetEqualFoldAttributeValues(attrGroupMemberPosix)
	for _, name := range id.resolvedNames {
		if containsFold(stored, name) {
			return name
		}
	}
	if len(id.resolvedNames) > 0 {
		return id.resolvedNames[0]
	}
	return ""
}

// containsFold reports whether values holds want, ignoring case: LDAP login names
// and attribute values are compared case-insensitively by the matching rules the
// read path relies on.
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
// The confirmation is per attribute and uses the read path's own rule, so a target
// is confirmed by the attribute it wrote and not by another one that already held
// the principal (a diverged entry writes two attributes, and the second must not
// be confirmed by the first).
func (g *groupResourceType) groupEffects(ctx context.Context, l *zap.Logger, groupDN string, group *ldap3.Entry, id principalIdentity) membershipEffects {
	return membershipEffects{
		value: func(_ context.Context, attr string) ([]string, error) {
			return membershipValue(group, id, attr)
		},
		add: func(ctx context.Context, attr string, values []string) (bool, error) {
			req := ldap3.NewModifyRequest(groupDN, nil)
			req.Add(attr, values)
			return g.client.LdapModifyStrictAndConfirm(ctx, req, membershipAttrs, func(entry *ldap3.Entry) (bool, error) {
				return attributeHoldsPrincipal(entry, attr, id), nil
			})
		},
		remove: func(ctx context.Context, deletions []membershipDeletion) (bool, error) {
			req := ldap3.NewModifyRequest(groupDN, nil)
			for _, deletion := range deletions {
				req.Delete(deletion.attr, deletion.values)
			}
			// Gone from every attribute, not just from the ones this request named:
			// the decision was taken from a read, and something else may have added
			// the principal to a fourth place since. The read path's question is the
			// one that matters here, and it is stronger than the delete's own list.
			return g.client.LdapModifyStrictAndConfirm(ctx, req, membershipAttrs, func(entry *ldap3.Entry) (bool, error) {
				return !anyAttributeHoldsPrincipal(entry, id), nil
			})
		},
	}
}

// attributeHoldsPrincipal reports whether one attribute's stored values name the
// principal, by the read path's rule: a value that parses as a DN is the principal
// when it canonicalizes to the principal's DN, and a login-name value is the
// principal when the read path resolves it to the principal.
func attributeHoldsPrincipal(entry *ldap3.Entry, attr string, id principalIdentity) bool {
	for _, value := range entry.GetEqualFoldAttributeValues(attr) {
		if parsed, err := ldap.CanonicalizeDN(value); err == nil {
			if strings.EqualFold(parsed.String(), id.dn) {
				return true
			}
			continue
		}
		if id.resolvesName(value) {
			return true
		}
	}
	return false
}

// anyAttributeHoldsPrincipal reports whether the group holds the principal in any
// of the membership attributes. It is the question the read path answers, and the
// one the inherited-membership traversal asks of each nested group.
func anyAttributeHoldsPrincipal(entry *ldap3.Entry, id principalIdentity) bool {
	return slices.ContainsFunc(membershipAttrs, func(attr string) bool {
		return attributeHoldsPrincipal(entry, attr, id)
	})
}

// groupHoldsPrincipal reports whether the read path would report id.dn as a direct
// member of this group. It is the post-condition check: it asks "would a sync see
// this membership?" rather than "did the server return success?".
//
// The resolution it needs -- which of the principal's names map back to it -- was
// done once when the principal's identity was resolved, so this performs no I/O
// and, in particular, no search that would take a second pooled connection while
// the modify's connection is held.
//
// A plain DN string comparison is deliberately not the check: CanonicalizeDN
// lowercases values only for the attribute types in caseInsensitiveAttrs, so the
// read path is the authority here, not our string handling.
func groupHoldsPrincipal(entry *ldap3.Entry, id principalIdentity) bool {
	return anyAttributeHoldsPrincipal(entry, id)
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
				// Reported, not skipped: the entry itself showed membership in this
				// attribute, so half-writing the entry and calling it done would
				// leave one of its two consumer views un-maintained.
				//
				// Note for the operator and for the next call: if an earlier target
				// was already written, rule 2 short-circuits later grants on this
				// group (the principal is present in the attribute that was written)
				// and answers GrantAlreadyExists without retrying this one. Completing
				// such an entry means writing the refused attribute out of band.
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

// decideRevokeOutcome renders the result of a revoke once the group holds no
// direct membership for the principal.
//
// removed says whether this call removed one. The one membership that still keeps
// the answer from being a success is the user's primary group: the connector itself
// reports that membership, from the user entry's gidNumber, and no write to this
// group can remove it, so answering "already revoked" would deny a membership the
// connector reports. It is pure, so the precedence is testable without a directory.
//
// A membership held only through a nested group is deliberately not this
// connector's business: the read path reports it through expansion, and revoking it
// means revoking the membership of the source group. The README says so.
func decideRevokeOutcome(removed bool, primaryGroup bool, groupDN string, principalDN string) (annotations.Annotations, error) {
	if primaryGroup {
		if removed {
			return nil, fmt.Errorf(
				"baton-ldap: removed the direct membership of %q from group %q, but the membership is also the user's primary group (gidNumber), so change the user's gidNumber instead",
				principalDN, groupDN)
		}
		return nil, fmt.Errorf(
			"baton-ldap: cannot revoke %q from group %q: the membership is the user's primary group (gidNumber), so change the user's gidNumber instead",
			principalDN, groupDN)
	}

	if removed {
		// The direct membership, which was the whole of the principal's membership
		// in this group, is gone.
		return nil, nil
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

// isNotFound reports whether err means "no such entry". LdapGet wraps the
// server's noSuchObject in codes.NotFound, and a caller-supplied DN can raise
// either.
func isNotFound(err error) bool {
	return ldap3.IsErrorAnyOf(err, ldap3.LDAPResultNoSuchObject) || status.Code(err) == codes.NotFound
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

	state := membershipState(group, id)
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

	state := membershipState(group, id)
	plan := planGroupMembership(state)

	if plan.dynamic {
		return nil, fmt.Errorf("baton-ldap: cannot revoke membership in dynamic groupOfURLs group %q directly", groupDN)
	}

	if !plan.present {
		primary, err := g.primaryGroupMember(ctx, group, principalDN)
		if err != nil {
			return nil, err
		}
		return decideRevokeOutcome(false, primary, groupDN, id.dn)
	}

	deletions := revokeDeletions(plan, state.principalValues)
	stale, err := revokeMembership(ctx, l, deletions, g.groupEffects(ctx, l, groupDN, group, id))
	if err != nil {
		return nil, fmt.Errorf("ldap-connector: failed to revoke group membership in %q: %w", groupDN, err)
	}

	// stale means the server had nothing to delete, so this call removed nothing --
	// whatever is true of the membership now, it is not this call's doing.
	removed := !stale

	if stale {
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
		if planGroupMembership(membershipState(fresh, id)).present {
			return nil, retryableMembershipError(
				"the membership of %q in %q is still present after the delete reported it absent", id.dn, groupDN)
		}
		group = fresh
	}

	// The direct membership is gone. That is not the whole answer: a principal who
	// is also a member through their own gidNumber is still a member of this group as
	// far as the read path is concerned, and the next sync would report the grant
	// again. Answer with that instead of a success the directory would contradict.
	// (A membership held only through a nested group is not revoked here: see
	// decideRevokeOutcome.)
	primary, err := g.primaryGroupMember(ctx, group, principalDN)
	if err != nil {
		return nil, err
	}

	return decideRevokeOutcome(removed, primary, groupDN, id.dn)
}
