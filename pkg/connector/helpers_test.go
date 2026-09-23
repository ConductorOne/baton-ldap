package connector

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
)

func TestParseDN(t *testing.T) {
	dn, err := ldap.ParseDN("cn=test,ou=test,dc=example,dc=com")
	require.NoError(t, err)
	require.Equal(t, "cn=test,ou=test,dc=example,dc=com", dn.String())

	dn, err = ldap.ParseDN("dc=example,dc=com")
	require.NoError(t, err)
	require.Equal(t, "dc=example,dc=com", dn.String())

	dn, err = ldap.ParseDN("ou=example")
	require.NoError(t, err)
	require.Equal(t, "ou=example", dn.String())
}

// TestToAttrIfNotEmpty pins the create-account rule: a value the profile left
// unset produces no attribute at all, because an LDAP Add carrying a zero-length
// value is rejected on a Directory String attribute (result 21), stored verbatim
// on an IA5 String one, and gets the literal "<nil>" stored on either when the
// value is nil. Runs without Docker.
func TestToAttrIfNotEmpty(t *testing.T) {
	tests := []struct {
		name    string
		value   interface{}
		dropped bool
		want    []string
	}{
		{name: "nil is dropped", value: nil, dropped: true},
		{name: "empty string is dropped", value: "", dropped: true},
		{name: "non-empty string is kept", value: "Doe", want: []string{"Doe"}},
		{name: "empty byte slice is dropped", value: []byte{}, dropped: true},
		{name: "byte slice is kept", value: []byte("Doe"), want: []string{"Doe"}},
		{name: "empty string slice is dropped", value: []string{}, dropped: true},
		{name: "all-empty string slice is dropped", value: []string{"", ""}, dropped: true},
		{name: "empty entries are filtered from a string slice", value: []string{"a", "", "b"}, want: []string{"a", "b"}},
		{name: "empty any slice is dropped", value: []interface{}{}, dropped: true},
		{name: "all-empty any slice is dropped", value: []interface{}{"", nil}, dropped: true},
		{name: "empty entries are dropped from an any slice", value: []interface{}{"", ""}, dropped: true},
		{name: "a nil-only any slice is dropped", value: []interface{}{nil}, dropped: true},
		{name: "nil and empty entries are filtered from an any slice", value: []interface{}{nil, "a", "", nil}, want: []string{"a"}},
		{name: "a trailing nil does not hide the other entries", value: []interface{}{"a", nil}, want: []string{"a"}},
		{name: "a leading nil does not turn into the literal <nil>", value: []interface{}{nil, "a"}, want: []string{"a"}},
		// A list whose elements do not share a type is rendered per element, so
		// it cannot reach the type assertion that toVals would panic on.
		{name: "mixed-type entries are each rendered", value: []interface{}{"a", float64(1)}, want: []string{"a", "1"}},
		{name: "a leading nil does not expose the rest to a mixed-type panic", value: []interface{}{nil, "a", float64(1)}, want: []string{"a", "1"}},
		{name: "an any entry that renders empty is dropped", value: []interface{}{[]byte{}}, dropped: true},
		{name: "false is a real value and is kept", value: false, want: []string{"false"}},
		// structpb is the only source of these values and produces numbers only
		// as float64, which toAttr renders with %f. A profile 0 is therefore sent
		// as "0.000000" and is kept, not treated as empty.
		{name: "a zero number from a profile is kept", value: float64(0), want: []string{"0.000000"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attr, ok := toAttrIfNotEmpty("title", tc.value)
			if tc.dropped {
				require.False(t, ok)
				return
			}
			require.True(t, ok)
			require.Equal(t, "title", attr.Type)
			require.Equal(t, tc.want, attr.Vals)
		})
	}
}
