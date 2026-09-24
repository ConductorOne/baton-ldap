package connector

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/conductorone/baton-ldap/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestGroupMembershipPlan covers the decision table: what the entry's classes and
// its current membership values say about which attribute a membership belongs
// in.
func TestGroupMembershipPlan(t *testing.T) {
	ocs := func(names ...string) []string {
		return append([]string{"top"}, names...)
	}

	cases := []struct {
		name     string
		state    groupMembershipState
		dynamic  bool
		inferred bool
		present  bool
		targets  []string
	}{
		{
			name:    "dynamic group is never writable",
			state:   groupMembershipState{objectClasses: ocs("groupOfURLs", "groupOfNames"), member: []string{"cn=a"}},
			dynamic: true,
		},
		{
			name:    "principal already in member -> that attribute, present",
			state:   groupMembershipState{objectClasses: ocs("groupOfNames"), member: []string{"cn=a"}, principalIn: []string{attrGroupMember}},
			present: true,
			targets: []string{attrGroupMember},
		},
		{
			name: "principal in both attributes -> both targeted",
			state: groupMembershipState{
				objectClasses: ocs("groupOfNames", "posixGroup"),
				member:        []string{"cn=a"},
				memberUID:     []string{"a"},
				principalIn:   []string{attrGroupMemberPosix, attrGroupMember},
			},
			present: true,
			targets: []string{attrGroupMember, attrGroupMemberPosix},
		},
		{
			name:    "groupOfNames group uses member",
			state:   groupMembershipState{objectClasses: ocs("groupOfNames"), member: []string{"cn=a"}},
			targets: []string{attrGroupMember},
		},
		{
			name:    "groupOfNames group stored lowercase uses member",
			state:   groupMembershipState{objectClasses: ocs("groupofnames"), member: []string{"cn=a"}},
			targets: []string{attrGroupMember},
		},
		{
			name:    "groupOfUniqueNames group uses uniqueMember",
			state:   groupMembershipState{objectClasses: ocs("groupOfUniqueNames"), uniqueMember: []string{"cn=a"}},
			targets: []string{attrGroupUniqueMember},
		},
		{
			name:    "structural posixGroup uses memberUid",
			state:   groupMembershipState{objectClasses: ocs("posixGroup"), memberUID: []string{"a"}},
			targets: []string{attrGroupMemberPosix},
		},
		{
			name:    "rfc2307bis coexist entry using memberUid follows its content",
			state:   groupMembershipState{objectClasses: ocs("groupofnames", "posixgroup"), memberUID: []string{"a"}},
			targets: []string{attrGroupMemberPosix},
		},
		{
			name:    "rfc2307bis coexist entry using member follows its content",
			state:   groupMembershipState{objectClasses: ocs("groupofnames", "posixgroup"), member: []string{"cn=a"}},
			targets: []string{attrGroupMember},
		},
		{
			name:    "diverged entry is ordered by the documented order, member first",
			state:   groupMembershipState{objectClasses: ocs("groupofnames", "posixgroup"), member: []string{"cn=a"}, memberUID: []string{"b"}},
			targets: []string{attrGroupMember, attrGroupMemberPosix},
		},
		{
			name:     "empty groupOfNames -> member (the reported bug)",
			state:    groupMembershipState{objectClasses: ocs("groupOfNames")},
			inferred: true,
			targets:  []string{attrGroupMember, attrGroupUniqueMember, attrGroupMemberPosix},
		},
		{
			name:     "empty lowercase groupofnames -> member (same bug, lowercase form)",
			state:    groupMembershipState{objectClasses: ocs("groupofnames")},
			inferred: true,
			targets:  []string{attrGroupMember, attrGroupUniqueMember, attrGroupMemberPosix},
		},
		{
			name:     "empty groupOfUniqueNames only -> uniqueMember first",
			state:    groupMembershipState{objectClasses: ocs("groupOfUniqueNames")},
			inferred: true,
			targets:  []string{attrGroupUniqueMember, attrGroupMember, attrGroupMemberPosix},
		},
		{
			name:     "empty structural posixGroup only -> memberUid first",
			state:    groupMembershipState{objectClasses: ocs("posixGroup")},
			inferred: true,
			targets:  []string{attrGroupMemberPosix, attrGroupMember, attrGroupUniqueMember},
		},
		{
			name:     "empty rfc2307bis coexist -> member first (DN clients), then memberUid",
			state:    groupMembershipState{objectClasses: ocs("groupofnames", "posixgroup")},
			inferred: true,
			targets:  []string{attrGroupMember, attrGroupUniqueMember, attrGroupMemberPosix},
		},
		{
			name:     "empty FreeIPA group -> member",
			state:    groupMembershipState{objectClasses: ocs("groupofnames", "posixgroup", "ipausergroup", "nestedgroup")},
			inferred: true,
			targets:  []string{attrGroupMember, attrGroupUniqueMember, attrGroupMemberPosix},
		},
		{
			name:     "empty AD group -> member",
			state:    groupMembershipState{objectClasses: ocs("group")},
			inferred: true,
			targets:  []string{attrGroupMember, attrGroupUniqueMember, attrGroupMemberPosix},
		},
		{
			name:     "unrecognised entry still falls back to the documented order",
			state:    groupMembershipState{objectClasses: ocs("myGroup")},
			inferred: true,
			targets:  []string{attrGroupMember, attrGroupUniqueMember, attrGroupMemberPosix},
		},
		{
			name:     "no objectClasses at all (hidden by an ACL) still orders",
			state:    groupMembershipState{},
			inferred: true,
			targets:  []string{attrGroupMember, attrGroupUniqueMember, attrGroupMemberPosix},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := planGroupMembership(tc.state)
			require.Equal(t, tc.dynamic, got.dynamic, "dynamic")
			require.Equal(t, tc.present, got.present, "present")
			if tc.dynamic {
				return
			}
			require.Equal(t, tc.inferred, got.inferred, "inferred")
			require.Equal(t, tc.targets, got.targets, "targets")
		})
	}
}

// TestGroupMembershipPlanCasingInvariance pins the regression that defeated the
// earlier objectClass-precedence approach: the spelling of a stored objectClass
// must not change the decision for a populated group. The same logical entry gets
// the same plan whatever the directory's spelling of posixGroup and groupOfNames.
func TestGroupMembershipPlanCasingInvariance(t *testing.T) {
	for _, spelling := range [][]string{
		{"top", "posixGroup", "groupOfNames"},
		{"top", "posixgroup", "groupofnames"},
		{"top", "posixGroup", "groupofnames"},
		{"top", "posixgroup", "groupOfNames"},
	} {
		empty := planGroupMembership(groupMembershipState{objectClasses: spelling})
		require.Equal(t, []string{attrGroupMember, attrGroupUniqueMember, attrGroupMemberPosix}, empty.targets, "spelling %v", spelling)
		require.True(t, empty.inferred, "spelling %v", spelling)

		withMemberUID := planGroupMembership(groupMembershipState{objectClasses: spelling, memberUID: []string{"a"}})
		require.Equal(t, []string{attrGroupMemberPosix}, withMemberUID.targets, "spelling %v", spelling)
		require.False(t, withMemberUID.inferred, "spelling %v", spelling)

		// A present membership is also spelling-independent, in both attributes.
		present := planGroupMembership(groupMembershipState{
			objectClasses: spelling,
			memberUID:     []string{"a"},
			principalIn:   []string{attrGroupMemberPosix},
		})
		require.True(t, present.present, "spelling %v", spelling)
		require.Equal(t, []string{attrGroupMemberPosix}, present.targets, "spelling %v", spelling)
	}
}

// ldapCodeError builds the error go-ldap returns for a server result code, so the
// loops can be driven through their real error classification.
func ldapCodeError(code uint16, message string) error {
	return &ldap3.Error{ResultCode: code, Err: errors.New(message)}
}

func testLogger() *zap.Logger { return zap.NewNop() }

// resolvingIdentity returns the identity with every name candidate resolved to the
// principal, which is the case the read path decides with its uid-then-cn search
// when no other entry claims the name.
func resolvingIdentity(id principalIdentity) principalIdentity {
	id.resolvedNames = id.nameCandidates()
	return id
}


// fakeEffects records what the loops did and answers with what the test says a
// directory would have answered.
type fakeEffects struct {
	// values is the answer for each attribute's value request. An attribute that
	// is not listed is a test error: the loop must not ask for a value it does not
	// write.
	values map[string][]string

	addCalls    []membershipDeletion
	add         func(attr string, values []string) (bool, error)
	removeCalls [][]membershipDeletion
	remove      func(deletions []membershipDeletion) (bool, error)
}

func (f *fakeEffects) effects() membershipEffects {
	return membershipEffects{
		value: func(_ context.Context, attr string) ([]string, error) {
			values, ok := f.values[attr]
			if !ok {
				return nil, fmt.Errorf("test: unexpected value request for attribute %q", attr)
			}
			return values, nil
		},
		add: func(_ context.Context, attr string, values []string) (bool, error) {
			f.addCalls = append(f.addCalls, membershipDeletion{attr: attr, values: values})
			if f.add == nil {
				return true, nil
			}
			return f.add(attr, values)
		},
		remove: func(_ context.Context, deletions []membershipDeletion) (bool, error) {
			f.removeCalls = append(f.removeCalls, deletions)
			if f.remove == nil {
				return true, nil
			}
			return f.remove(deletions)
		},
	}
}

func (f *fakeEffects) attempted() []string {
	rv := make([]string, 0, len(f.addCalls))
	for _, call := range f.addCalls {
		rv = append(rv, call.attr)
	}
	return rv
}

// TestGrantLoop drives the grant attempt/verify loop through its failure modes
// with fakes: the schema rejection that advances, the rejection that exhausts the
// candidates, the already-present answer, the diverged entry that writes every
// populated attribute, and -- the one that matters most -- a write the server
// accepted but the read did not confirm.
func TestGrantLoop(t *testing.T) {
	ctx := t.Context()
	l := testLogger()
	candidates := []string{attrGroupMember, attrGroupUniqueMember, attrGroupMemberPosix}

	t.Run("a schema rejection advances to the next candidate", func(t *testing.T) {
		fake := &fakeEffects{
			values: map[string][]string{
				attrGroupMember:       {"cn=a,dc=example,dc=org"},
				attrGroupUniqueMember: {"cn=a,dc=example,dc=org"},
			},
			add: func(attr string, _ []string) (bool, error) {
				if attr == attrGroupMember {
					return false, ldapCodeError(ldap3.LDAPResultObjectClassViolation, "attribute 'member' not allowed")
				}
				return true, nil
			},
		}

		annos, err := grantMembership(ctx, l, candidates, attemptCandidates, fake.effects())
		require.NoError(t, err)
		require.Nil(t, annos)
		require.Equal(t, []string{attrGroupMember, attrGroupUniqueMember}, fake.attempted())
	})

	t.Run("an undefined attribute type is also a rejection to learn from", func(t *testing.T) {
		fake := &fakeEffects{
			values: map[string][]string{
				attrGroupMember:       {"cn=a,dc=example,dc=org"},
				attrGroupUniqueMember: {"cn=a,dc=example,dc=org"},
			},
			add: func(attr string, _ []string) (bool, error) {
				if attr == attrGroupMember {
					return false, ldapCodeError(ldap3.LDAPResultUndefinedAttributeType, "no such attribute type")
				}
				return true, nil
			},
		}

		_, err := grantMembership(ctx, l, candidates, attemptCandidates, fake.effects())
		require.NoError(t, err)
		require.Equal(t, []string{attrGroupMember, attrGroupUniqueMember}, fake.attempted())
	})

	t.Run("every candidate rejected names them all", func(t *testing.T) {
		fake := &fakeEffects{
			values: map[string][]string{
				attrGroupMember:       {"cn=a,dc=example,dc=org"},
				attrGroupUniqueMember: {"cn=a,dc=example,dc=org"},
				attrGroupMemberPosix:  {"a"},
			},
			add: func(_ string, _ []string) (bool, error) {
				return false, ldapCodeError(ldap3.LDAPResultObjectClassViolation, "not allowed")
			},
		}

		_, err := grantMembership(ctx, l, candidates, attemptCandidates, fake.effects())
		require.Error(t, err)
		for _, attr := range candidates {
			require.ErrorContains(t, err, attr)
		}
		require.ErrorContains(t, err, "not allowed")
		require.Equal(t, candidates, fake.attempted())
	})

	t.Run("an already-present value answers already-exists without a second write", func(t *testing.T) {
		fake := &fakeEffects{
			values: map[string][]string{attrGroupMember: {"cn=a,dc=example,dc=org"}},
			add: func(_ string, _ []string) (bool, error) {
				return false, ldapCodeError(ldap3.LDAPResultAttributeOrValueExists, "value exists")
			},
		}

		annos, err := grantMembership(ctx, l, candidates, attemptCandidates, fake.effects())
		require.NoError(t, err)
		require.True(t, annos.Contains(&v2.GrantAlreadyExists{}))
		require.Len(t, fake.addCalls, 1)
	})

	t.Run("an unconfirmed write is retryable and writes no second attribute", func(t *testing.T) {
		fake := &fakeEffects{
			values: map[string][]string{attrGroupMember: {"cn=a,dc=example,dc=org"}},
			add: func(_ string, _ []string) (bool, error) {
				// Accepted, but no read confirmed it.
				return false, nil
			},
		}

		annos, err := grantMembership(ctx, l, candidates, attemptCandidates, fake.effects())
		require.Error(t, err)
		require.Nil(t, annos)
		require.Equal(t, codes.Unavailable, status.Code(err))
		require.Equal(t, []string{attrGroupMember}, fake.attempted(),
			"an unconfirmed write must not be followed by a write to another attribute")
	})

	t.Run("a diverged entry writes every populated attribute", func(t *testing.T) {
		fake := &fakeEffects{
			values: map[string][]string{
				attrGroupMember:      {"cn=new,dc=example,dc=org"},
				attrGroupMemberPosix: {"new"},
			},
		}

		annos, err := grantMembership(ctx, l,
			[]string{attrGroupMember, attrGroupMemberPosix}, attemptEveryTarget, fake.effects())
		require.NoError(t, err)
		require.Nil(t, annos)
		require.Equal(t, []string{attrGroupMember, attrGroupMemberPosix}, fake.attempted())
	})

	t.Run("a populated attribute the entry does not permit is reported, not skipped", func(t *testing.T) {
		fake := &fakeEffects{
			values: map[string][]string{
				attrGroupMember:      {"cn=new,dc=example,dc=org"},
				attrGroupMemberPosix: {"new"},
			},
			add: func(attr string, _ []string) (bool, error) {
				if attr == attrGroupMemberPosix {
					return false, ldapCodeError(ldap3.LDAPResultObjectClassViolation, "not allowed")
				}
				return true, nil
			},
		}

		_, err := grantMembership(ctx, l,
			[]string{attrGroupMember, attrGroupMemberPosix}, attemptEveryTarget, fake.effects())
		require.Error(t, err)
		require.ErrorContains(t, err, attrGroupMemberPosix)
	})

	t.Run("a non-schema error stops the loop", func(t *testing.T) {
		fake := &fakeEffects{
			values: map[string][]string{attrGroupMember: {"cn=a,dc=example,dc=org"}},
			add: func(_ string, _ []string) (bool, error) {
				return false, ldapCodeError(ldap3.LDAPResultInvalidAttributeSyntax, "bad value")
			},
		}

		_, err := grantMembership(ctx, l, candidates, attemptCandidates, fake.effects())
		require.Error(t, err)
		require.Equal(t, []string{attrGroupMember}, fake.attempted(),
			"a syntax error is not a signal to try another attribute")
	})
}

// TestRevokeTargets covers the delete half: one atomic request naming the exact
// stored values of every attribute that holds the principal, and the three
// answers the server can give.
func TestRevokeTargets(t *testing.T) {
	ctx := t.Context()
	l := testLogger()

	state := groupMembershipState{
		member:      []string{"cn=a,dc=example,dc=org", "cn=b,dc=example,dc=org"},
		memberUID:   []string{"a"},
		principalIn: []string{attrGroupMember, attrGroupMemberPosix},
		principalValues: map[string][]string{
			attrGroupMember:      {"cn=A,DC=Example,DC=Org"},
			attrGroupMemberPosix: {"a"},
		},
	}
	plan := planGroupMembership(state)
	require.True(t, plan.present)

	t.Run("one request naming the exact stored values of both attributes", func(t *testing.T) {
		fake := &fakeEffects{}

		stale, err := revokeMembership(ctx, l, revokeDeletions(plan, state.principalValues), fake.effects())
		require.NoError(t, err)
		require.False(t, stale)
		require.Len(t, fake.removeCalls, 1)
		require.Equal(t, []membershipDeletion{
			{attr: attrGroupMember, values: []string{"cn=A,DC=Example,DC=Org"}},
			{attr: attrGroupMemberPosix, values: []string{"a"}},
		}, fake.removeCalls[0], "the values deleted are the stored strings, not a normalized form of them")
	})

	t.Run("a stale read (16) is reported, not swallowed", func(t *testing.T) {
		fake := &fakeEffects{remove: func(_ []membershipDeletion) (bool, error) {
			return false, ldapCodeError(ldap3.LDAPResultNoSuchAttribute, "not present")
		}}

		stale, err := revokeMembership(ctx, l, revokeDeletions(plan, state.principalValues), fake.effects())
		require.NoError(t, err)
		require.True(t, stale)
	})

	t.Run("a delete that did not remove the membership is retryable", func(t *testing.T) {
		fake := &fakeEffects{remove: func(_ []membershipDeletion) (bool, error) {
			return false, nil
		}}

		_, err := revokeMembership(ctx, l, revokeDeletions(plan, state.principalValues), fake.effects())
		require.Error(t, err)
		require.Equal(t, codes.Unavailable, status.Code(err))
	})

	t.Run("any other error is returned as it is", func(t *testing.T) {
		fake := &fakeEffects{remove: func(_ []membershipDeletion) (bool, error) {
			return false, ldapCodeError(ldap3.LDAPResultInsufficientAccessRights, "denied")
		}}

		_, err := revokeMembership(ctx, l, revokeDeletions(plan, state.principalValues), fake.effects())
		require.Error(t, err)
		require.NotEqual(t, codes.Unavailable, status.Code(err))
	})

	t.Run("a target with no matched value is not included", func(t *testing.T) {
		deletions := revokeDeletions(groupMembershipPlan{targets: []string{attrGroupMember, attrGroupMemberPosix}}, map[string][]string{
			attrGroupMember: {"cn=a,dc=example,dc=org"},
		})
		require.Equal(t, []membershipDeletion{{attr: attrGroupMember, values: []string{"cn=a,dc=example,dc=org"}}}, deletions)
	})
}

// TestPinnedGrant covers the operator override: which attribute a pinned grant
// targets, that a rejection of the pin is fatal (no fall-through to an attribute
// the operator did not choose), and that a pin is ignored by the decision itself
// when the principal is already a member.
func TestPinnedGrant(t *testing.T) {
	ctx := t.Context()

	t.Run("an unset field and auto are the same thing", func(t *testing.T) {
		require.Equal(t, "", pinnedMemberAttribute(""))
		require.Equal(t, "", pinnedMemberAttribute(config.GroupMemberAttributeAuto))
		require.Equal(t, "", pinnedMemberAttribute("AUTO"))
	})

	t.Run("the pinned values are the attributes this connector writes", func(t *testing.T) {
		require.Equal(t, attrGroupMember, pinnedMemberAttribute(config.GroupMemberAttributeMember))
		require.Equal(t, attrGroupUniqueMember, pinnedMemberAttribute(config.GroupMemberAttributeUniqueMember))
		require.Equal(t, attrGroupMemberPosix, pinnedMemberAttribute(config.GroupMemberAttributeMemberUID))
	})

	t.Run("a pin replaces the plan's candidates", func(t *testing.T) {
		// An inferred plan on an empty groupOfNames would otherwise try all three.
		plan := planGroupMembership(groupMembershipState{objectClasses: []string{"top", "groupOfNames"}})
		require.True(t, plan.inferred)

		targets, mode := plan.grantTargets(attrGroupMemberPosix)
		require.Equal(t, []string{attrGroupMemberPosix}, targets)
		require.Equal(t, attemptCandidates, mode)
	})

	t.Run("without a pin the entry's content is written in full", func(t *testing.T) {
		plan := planGroupMembership(groupMembershipState{
			objectClasses: []string{"top", "groupOfNames", "posixGroup"},
			member:        []string{"cn=a,dc=example,dc=org"},
			memberUID:     []string{"a"},
		})
		targets, mode := plan.grantTargets("")
		require.Equal(t, []string{attrGroupMember, attrGroupMemberPosix}, targets)
		require.Equal(t, attemptEveryTarget, mode)
	})

	t.Run("a rejection of the pin is fatal and writes nowhere else", func(t *testing.T) {
		fake := &fakeEffects{
			values: map[string][]string{attrGroupMemberPosix: {"a"}},
			add: func(_ string, _ []string) (bool, error) {
				return false, ldapCodeError(ldap3.LDAPResultObjectClassViolation, "attribute 'memberUid' not allowed")
			},
		}

		plan := planGroupMembership(groupMembershipState{objectClasses: []string{"top", "groupOfNames"}})
		targets, mode := plan.grantTargets(attrGroupMemberPosix)

		_, err := grantMembership(ctx, testLogger(), targets, mode, fake.effects())
		require.Error(t, err)
		require.ErrorContains(t, err, attrGroupMemberPosix)
		require.Equal(t, []string{attrGroupMemberPosix}, fake.attempted())
	})

	t.Run("a pin does not override an already-present membership", func(t *testing.T) {
		// The decision runs before the pin is applied, so a principal already in
		// the entry's own attribute is already a member whatever the pin says.
		plan := planGroupMembership(groupMembershipState{
			objectClasses: []string{"top", "groupOfNames"},
			member:        []string{"cn=a,dc=example,dc=org"},
			principalIn:   []string{attrGroupMember},
		})
		require.True(t, plan.present)
	})
}

// TestMemberUidForms covers the memberUid value form: which of the principal's
// login names is written, and that a stored value in either form is matched
// (and deleted) exactly as stored.
func TestMemberUidForms(t *testing.T) {
	entryWithMemberUID := func(values ...string) *ldap3.Entry {
		return &ldap3.Entry{
			DN: "cn=g,ou=groups,dc=example,dc=org",
			Attributes: []*ldap3.EntryAttribute{
				{Name: "objectClass", Values: []string{"top", "posixGroup"}},
				{Name: "cn", Values: []string{"g"}},
				{Name: "memberUid", Values: values},
			},
		}
	}
	principal := principalIdentity{
		dn:  "cn=alice smith,ou=users,dc=example,dc=org",
		uid: "asmith",
		cn:  "Alice Smith",
		rdn: "Alice Smith",
	}

	t.Run("the stored uid form is detected and deleted as stored", func(t *testing.T) {
		entry := entryWithMemberUID("asmith")
		matches := matchPrincipal(entry, resolvingIdentity(principal))
		require.Equal(t, []string{"asmith"}, matches[attrGroupMemberPosix])

		state := membershipState(entry, resolvingIdentity(principal))
		require.Equal(t, []string{attrGroupMemberPosix}, state.principalIn)
		require.Equal(t, []string{"asmith"}, state.principalValues[attrGroupMemberPosix])
	})

	t.Run("the stored cn form is detected and deleted as stored", func(t *testing.T) {
		entry := entryWithMemberUID("Alice Smith")
		matches := matchPrincipal(entry, resolvingIdentity(principal))
		require.Equal(t, []string{"Alice Smith"}, matches[attrGroupMemberPosix])
	})

	t.Run("matching ignores case", func(t *testing.T) {
		entry := entryWithMemberUID("ASMITH", "alice smith")
		matches := matchPrincipal(entry, resolvingIdentity(principal))
		require.Equal(t, []string{"ASMITH", "alice smith"}, matches[attrGroupMemberPosix])
	})

	t.Run("a different member is not matched", func(t *testing.T) {
		entry := entryWithMemberUID("bob")
		require.Empty(t, matchPrincipal(entry, resolvingIdentity(principal)))
		require.Empty(t, membershipState(entry, resolvingIdentity(principal)).principalIn)
	})

	t.Run("the form the entry already uses is written", func(t *testing.T) {
		resolved := resolvingIdentity(principal)
		require.Equal(t, "Alice Smith", memberUIDValue(entryWithMemberUID("Alice Smith"), resolved))
		require.Equal(t, "asmith", memberUIDValue(entryWithMemberUID("asmith"), resolved))
	})

	t.Run("an entry with no memberUid values gets the uid", func(t *testing.T) {
		require.Equal(t, "asmith", memberUIDValue(entryWithMemberUID(), resolvingIdentity(principal)))
	})

	t.Run("a principal with no uid falls back to the first RDN value", func(t *testing.T) {
		noUID := resolvingIdentity(principalIdentity{dn: principal.dn, cn: "Alice Smith", rdn: "Alice Smith"})
		require.Equal(t, "Alice Smith", memberUIDValue(entryWithMemberUID(), noUID))
	})

	t.Run("value selection for the DN-valued attributes is the principal's DN", func(t *testing.T) {
		values, err := membershipValue(entryWithMemberUID(), resolvingIdentity(principal), attrGroupMember)
		require.NoError(t, err)
		require.Equal(t, []string{principal.dn}, values)

		values, err = membershipValue(entryWithMemberUID(), resolvingIdentity(principal), attrGroupUniqueMember)
		require.NoError(t, err)
		require.Equal(t, []string{principal.dn}, values)

		values, err = membershipValue(entryWithMemberUID(), resolvingIdentity(principal), attrGroupMemberPosix)
		require.NoError(t, err)
		require.Equal(t, []string{"asmith"}, values)

		_, err = membershipValue(entryWithMemberUID(), resolvingIdentity(principal), "memberOf")
		require.Error(t, err)
	})
}

// TestMatchPrincipalDNValues covers the DN-valued attributes: canonical
// comparison, the bare-login-name fallback the read path also applies, and that
// an inherited membership is not a direct one.
func TestMatchPrincipalDNValues(t *testing.T) {
	entryWith := func(attr string, values ...string) *ldap3.Entry {
		return &ldap3.Entry{
			DN: "cn=g,ou=groups,dc=example,dc=org",
			Attributes: []*ldap3.EntryAttribute{
				{Name: attr, Values: values},
			},
		}
	}
	principal := principalIdentity{dn: "cn=alice,ou=users,dc=example,dc=org", uid: "alice", cn: "alice", rdn: "alice"}

	t.Run("a differently cased DN is the same member", func(t *testing.T) {
		matches := matchPrincipal(entryWith(attrGroupMember, "CN=Alice,OU=Users,DC=Example,DC=Org"), resolvingIdentity(principal))
		require.Equal(t, []string{"CN=Alice,OU=Users,DC=Example,DC=Org"}, matches[attrGroupMember])
	})

	t.Run("another member is not matched", func(t *testing.T) {
		require.Empty(t, matchPrincipal(entryWith(attrGroupMember, "cn=bob,ou=users,dc=example,dc=org"), resolvingIdentity(principal)))
	})

	t.Run("a bare login name in a DN-valued attribute counts as the member", func(t *testing.T) {
		// The read path resolves a value that does not parse as a DN through
		// findMember, so a directory with schema checking off that stored a bare
		// name in member still reports the membership.
		matches := matchPrincipal(entryWith(attrGroupUniqueMember, "alice"), resolvingIdentity(principal))
		require.Equal(t, []string{"alice"}, matches[attrGroupUniqueMember])
	})

	t.Run("a nested group is not the principal", func(t *testing.T) {
		require.Empty(t, matchPrincipal(entryWith(attrGroupMember, "cn=sub,ou=groups,dc=example,dc=org"), resolvingIdentity(principal)))
	})
}

// TestRevokeOutcome covers the precedence between the two guards and the two ways a
// revoke can end: with a direct membership removed by this call, or with none to
// remove. Neither may answer with a plain success while a membership the read path
// still reports -- a primary-group or inherited one -- remains.
func TestRevokeOutcome(t *testing.T) {
	const groupDN = "cn=g,ou=groups,dc=example,dc=org"
	const principalDN = "cn=alice,ou=users,dc=example,dc=org"

	t.Run("nothing remains, nothing removed -> already revoked", func(t *testing.T) {
		annos, err := decideRevokeOutcome(false, revokeAbsence{}, groupDN, principalDN)
		require.NoError(t, err)
		require.True(t, annos.Contains(&v2.GrantAlreadyRevoked{}))
	})

	t.Run("nothing remains, direct membership removed -> success", func(t *testing.T) {
		annos, err := decideRevokeOutcome(true, revokeAbsence{}, groupDN, principalDN)
		require.NoError(t, err)
		require.Nil(t, annos)
	})

	t.Run("the primary group remains -> reported, not revoked", func(t *testing.T) {
		annos, err := decideRevokeOutcome(false, revokeAbsence{primaryGroup: true}, groupDN, principalDN)
		require.Error(t, err)
		require.Nil(t, annos)
		require.ErrorContains(t, err, "primary group")
	})

	t.Run("the primary group remains after a direct delete -> reported, not removed", func(t *testing.T) {
		annos, err := decideRevokeOutcome(true, revokeAbsence{primaryGroup: true}, groupDN, principalDN)
		require.Error(t, err)
		require.Nil(t, annos)
		require.ErrorContains(t, err, "removed the direct membership")
		require.ErrorContains(t, err, "primary group")
	})

	t.Run("an inherited membership names its source", func(t *testing.T) {
		annos, err := decideRevokeOutcome(false,
			revokeAbsence{inheritedVia: "cn=sub,ou=groups,dc=example,dc=org"}, groupDN, principalDN)
		require.Error(t, err)
		require.Nil(t, annos)
		require.ErrorContains(t, err, "cn=sub,ou=groups,dc=example,dc=org")
	})

	t.Run("an inherited membership that outlives a direct delete is reported", func(t *testing.T) {
		annos, err := decideRevokeOutcome(true,
			revokeAbsence{inheritedVia: "cn=sub,ou=groups,dc=example,dc=org"}, groupDN, principalDN)
		require.Error(t, err)
		require.Nil(t, annos)
		require.ErrorContains(t, err, "removed the direct membership")
		require.ErrorContains(t, err, "inherited via")
	})

	t.Run("the primary group wins when both guards match", func(t *testing.T) {
		annos, err := decideRevokeOutcome(false,
			revokeAbsence{primaryGroup: true, inheritedVia: "cn=sub,ou=groups,dc=example,dc=org"}, groupDN, principalDN)
		require.Error(t, err)
		require.Nil(t, annos)
		require.ErrorContains(t, err, "primary group")
	})

	t.Run("a search cut short by a cap is not already revoked", func(t *testing.T) {
		annos, err := decideRevokeOutcome(false, revokeAbsence{truncated: true}, groupDN, principalDN)
		require.Error(t, err)
		require.Nil(t, annos)
		require.ErrorContains(t, err, "inherited-membership search stopped early")
	})
}

// TestGrantIsDirectOnly covers the one thing the received grant's Sources are used
// for: the negative case they can settle without a search. They are never used to
// name a source, because they come from the last sync -- a nested membership
// removed outside C1 would otherwise produce a permanent "inherited via B" error
// for a membership that no longer exists.
func TestGrantIsDirectOnly(t *testing.T) {
	const ownEntitlement = "group:cn=outer,ou=groups,dc=example,dc=org:member"
	const subgroupEntitlement = "group:cn=inner,ou=groups,dc=example,dc=org:member"

	grantWith := func(sources map[string]bool) *v2.Grant {
		rv := &v2.Grant{Entitlement: &v2.Entitlement{Id: ownEntitlement}}
		if sources == nil {
			return rv
		}
		built := make(map[string]*v2.GrantSources_GrantSource, len(sources))
		for id, direct := range sources {
			built[id] = &v2.GrantSources_GrantSource{IsDirect: direct}
		}
		rv.Sources = &v2.GrantSources{Sources: built}
		return rv
	}

	t.Run("no sources answers nothing, so the walk decides", func(t *testing.T) {
		require.False(t, grantIsDirectOnly(grantWith(nil)))
	})

	t.Run("this entitlement as the only direct source is not inherited", func(t *testing.T) {
		require.True(t, grantIsDirectOnly(grantWith(map[string]bool{ownEntitlement: true})))
	})

	t.Run("another entitlement contributing means the walk has to run", func(t *testing.T) {
		require.False(t, grantIsDirectOnly(grantWith(map[string]bool{subgroupEntitlement: false})))
	})

	t.Run("a direct source alongside another one is not direct-only", func(t *testing.T) {
		require.False(t, grantIsDirectOnly(grantWith(map[string]bool{subgroupEntitlement: false, ownEntitlement: true})))
	})

	t.Run("this entitlement named as not direct leaves the walk to decide", func(t *testing.T) {
		require.False(t, grantIsDirectOnly(grantWith(map[string]bool{ownEntitlement: false})))
	})

	t.Run("a grant without an entitlement id is never direct-only", func(t *testing.T) {
		require.False(t, grantIsDirectOnly(&v2.Grant{
			Sources: &v2.GrantSources{Sources: map[string]*v2.GrantSources_GrantSource{
				ownEntitlement: {IsDirect: true},
			}},
		}))
	})
}

// TestNamedInheritedSources covers the entitlement-id parsing that turns the
// grant's Sources into group DNs to check live. They are hints, never the answer,
// which is why a key that is not a group membership entitlement is skipped rather
// than guessed at.
func TestNamedInheritedSources(t *testing.T) {
	const own = "group:cn=outer,ou=groups,dc=example,dc=org:member"

	grantWith := func(ids ...string) *v2.Grant {
		built := make(map[string]*v2.GrantSources_GrantSource, len(ids))
		for _, id := range ids {
			built[id] = &v2.GrantSources_GrantSource{}
		}
		return &v2.Grant{Sources: &v2.GrantSources{Sources: built}}
	}

	t.Run("no sources names nothing", func(t *testing.T) {
		require.Empty(t, namedInheritedSources(&v2.Grant{}, own))
	})

	t.Run("this group's own entitlement is not a source", func(t *testing.T) {
		require.Empty(t, namedInheritedSources(grantWith(own), own))
	})

	t.Run("another group's entitlement yields its DN", func(t *testing.T) {
		require.Equal(t, []string{"cn=inner,ou=groups,dc=example,dc=org"},
			namedInheritedSources(grantWith("group:cn=inner,ou=groups,dc=example,dc=org:member"), own))
	})

	t.Run("a source outside the group search scope is still named", func(t *testing.T) {
		// The DN is what makes this case reachable at all: the walk searches a
		// subtree, this does not.
		require.Equal(t, []string{"cn=elsewhere,dc=example,dc=org"},
			namedInheritedSources(grantWith("group:cn=elsewhere,dc=example,dc=org:member"), own))
	})

	t.Run("keys that are not group membership entitlements are skipped", func(t *testing.T) {
		require.Empty(t, namedInheritedSources(grantWith(
			"user:cn=alice,ou=users,dc=example,dc=org",     // not a group
			"group:not a dn:member",                        // not a DN
			"group:cn=g,ou=groups,dc=example,dc=org:admin", // not the member entitlement
			"group:cn=g,ou=groups,dc=example,dc=org",       // no entitlement segment
		), own))
	})

	t.Run("several sources are all returned", func(t *testing.T) {
		require.ElementsMatch(t, []string{
			"cn=inner,ou=groups,dc=example,dc=org",
			"cn=other,ou=groups,dc=example,dc=org",
		}, namedInheritedSources(grantWith(
			"group:cn=inner,ou=groups,dc=example,dc=org:member",
			"group:cn=other,ou=groups,dc=example,dc=org:member",
		), own))
	})
}

// TestInheritedWalkFilters covers the two filters the walk issues. The walk must
// reach the directory with a filter that names the principal's own forms (a
// memberUid value is a login name, not a DN) and with the group classes, so that a
// group of ten thousand users costs the same as a group of two.
func TestInheritedWalkFilters(t *testing.T) {
	id := principalIdentity{
		dn:            "cn=alice smith,ou=users,dc=example,dc=org",
		uid:           "asmith",
		cn:            "Alice Smith",
		rdn:           "Alice Smith",
		resolvedNames: []string{"asmith", "Alice Smith"},
	}

	t.Run("the direct holder filter names every resolved form in every attribute", func(t *testing.T) {
		filter := directHolderFilter(id)
		require.Equal(t,
			"(|(member=cn=alice smith,ou=users,dc=example,dc=org)(uniqueMember=cn=alice smith,ou=users,dc=example,dc=org)"+
				"(member=asmith)(uniqueMember=asmith)(memberUid=asmith)"+
				"(member=Alice Smith)(uniqueMember=Alice Smith)(memberUid=Alice Smith))",
			filter)
		_, err := ldap3.CompileFilter(filter)
		require.NoError(t, err)
	})

	t.Run("a principal with no resolved names is only looked for by DN", func(t *testing.T) {
		filter := directHolderFilter(principalIdentity{dn: id.dn})
		require.NotContains(t, filter, attrGroupMemberPosix)
		_, err := ldap3.CompileFilter(filter)
		require.NoError(t, err)
	})

	t.Run("the holder filter names both DN-valued attributes for every group", func(t *testing.T) {
		filter := holderFilter([]string{"cn=inner,ou=groups,dc=example,dc=org", "cn=other,ou=groups,dc=example,dc=org"})
		require.Equal(t,
			"(|(member=cn=inner,ou=groups,dc=example,dc=org)(uniqueMember=cn=inner,ou=groups,dc=example,dc=org)"+
				"(member=cn=other,ou=groups,dc=example,dc=org)(uniqueMember=cn=other,ou=groups,dc=example,dc=org))",
			filter)
		_, err := ldap3.CompileFilter(filter)
		require.NoError(t, err)
	})

	t.Run("filter values are escaped", func(t *testing.T) {
		filter := directHolderFilter(principalIdentity{dn: "cn=a*b(c),ou=users,dc=example,dc=org"})
		_, err := ldap3.CompileFilter(filter)
		require.NoError(t, err)
		require.Contains(t, filter, `\2a`)
	})
}

// TestInheritedTraversalTruncation covers the decision side of a walk that could
// not establish "not inherited": it must report that it stopped, never "already
// revoked". What makes the walk stop (a full page, or the depth cap) needs a
// directory and is covered by the large-group integration test.
func TestInheritedTraversalLookupCap(t *testing.T) {
	annos, err := decideRevokeOutcome(false, revokeAbsence{truncated: true},
		"cn=g,ou=groups,dc=example,dc=org", "cn=alice,ou=users,dc=example,dc=org")
	require.Error(t, err)
	require.Nil(t, annos)
	require.ErrorContains(t, err, "stopped early")
}

// TestMembershipBlastRadiusReport is a report, not an assertion. It prints what
// the previous selector would have chosen and what the new plan chooses for the
// same entry, so the compatibility surface of the change can be read in one
// place. The generated table goes in the pull request description.
func TestMembershipBlastRadiusReport(t *testing.T) {
	type classSet struct {
		name    string
		classes []string
	}
	type content struct {
		name            string
		members         []string
		memberUIDValues []string
	}

	classSets := []classSet{
		{name: "groupOfNames", classes: []string{"top", "groupOfNames"}},
		{name: "groupOfUniqueNames", classes: []string{"top", "groupOfUniqueNames"}},
		{name: "posixGroup", classes: []string{"top", "posixGroup"}},
		{name: "groupOfURLs+groupOfNames", classes: []string{"top", "groupOfURLs", "groupOfNames"}},
		{name: "groupOfNames+posixGroup (rfc2307bis)", classes: []string{"top", "groupOfNames", "posixGroup"}},
		{name: "group (AD)", classes: []string{"top", "group"}},
		{name: "groupOfNames+ipausergroup (FreeIPA)", classes: []string{"top", "groupofnames", "ipausergroup", "posixgroup"}},
	}
	contents := []content{
		{name: "empty"},
		{name: "member populated", members: []string{"cn=other,ou=users,dc=example,dc=org"}},
		{name: "memberUid populated", memberUIDValues: []string{"other"}},
		{name: "both populated", members: []string{"cn=other,ou=users,dc=example,dc=org"}, memberUIDValues: []string{"other"}},
	}

	var table strings.Builder
	table.WriteString("| objectClass | membership content | old selector wrote | new plan writes |\n")
	table.WriteString("| --- | --- | --- | --- |\n")

	for _, cs := range classSets {
		for _, c := range contents {
			plan := planGroupMembership(groupMembershipState{
				objectClasses: cs.classes,
				member:        c.members,
				uniqueMember:  nil,
				memberUID:     c.memberUIDValues,
			})

			newPlan := "error (dynamic)"
			switch {
			case plan.dynamic:
			case plan.present:
				newPlan = "already a member"
			case plan.inferred:
				newPlan = "try in order: " + strings.Join(plan.targets, ", ")
			default:
				newPlan = "write " + strings.Join(plan.targets, ", ")
			}

			fmt.Fprintf(&table, "| `%s` | %s | %s | %s |\n",
				cs.name, c.name, legacyMembershipAttribute(cs.classes), newPlan)
		}
	}

	table.WriteString("\nThe old selector is the `objectClass`-only chain on `main`: " +
		"`groupOfURLs` -> error, `posixGroup` -> `memberUid`, `ipausergroup` or a non-empty `objectGUID` -> `member`, " +
		"otherwise -> `uniqueMember`. The `objectGUID` probe cannot appear in this matrix (it reads the entry rather " +
		"than a class) and is gone in this change; where it matched, the old selector wrote `member` and so does the new plan.\n")

	t.Log("\n" + table.String())
}

// legacyMembershipAttribute is the attribute the pre-change selector wrote, kept
// here only to generate the compatibility table above.
func legacyMembershipAttribute(objectClasses []string) string {
	has := func(name string) bool { return slices.Contains(objectClasses, name) }
	switch {
	case has(objectClassGroupOfURLs):
		return "error (dynamic)"
	case has("posixGroup"):
		return attrGroupMemberPosix
	case has("ipausergroup"):
		return attrGroupMember
	default:
		return attrGroupUniqueMember
	}
}
