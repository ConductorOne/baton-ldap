package connector

import (
	"testing"

	"go.uber.org/zap"
)

func TestResolveAttrName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"first_name", "givenName"},
		{"last_name", "sn"},
		{"display_name", "displayName"},
		{"middle_name", "middleName"},
		{"job_title", "title"},
		{"department", "department"},
		{"division", "division"},
		{"company", "company"},
		{"employee_id", "employeeID"},
		{"employee_number", "employeeNumber"},
		{"employment_type", "employeeType"},
		{"email", "mail"},
		// Extension attributes should pass through directly.
		{"extensionAttribute1", "extensionAttribute1"},
		{"extensionAttribute15", "extensionAttribute15"},
		// Arbitrary custom attributes should pass through.
		{"customField", "customField"},
		{"telephoneNumber", "telephoneNumber"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := resolveAttrName(tt.input)
			if result != tt.expected {
				t.Errorf("resolveAttrName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBuildLDAPChanges(t *testing.T) {
	l := zap.NewNop()

	t.Run("standard attributes", func(t *testing.T) {
		attrs := map[string]string{
			"first_name": "Jane",
			"last_name":  "Doe",
		}
		mask := []string{"first_name", "last_name"}

		changes := buildLDAPChanges(l, attrs, mask)
		if len(changes) != 2 {
			t.Fatalf("expected 2 changes, got %d", len(changes))
		}

		// Verify LDAP attribute names are used.
		attrNames := make(map[string]bool)
		for _, c := range changes {
			attrNames[c.Modification.Type] = true
		}
		if !attrNames["givenName"] {
			t.Error("expected givenName in changes")
		}
		if !attrNames["sn"] {
			t.Error("expected sn in changes")
		}
	})

	t.Run("extension attributes pass through", func(t *testing.T) {
		attrs := map[string]string{
			"extensionAttribute1":  "value1",
			"extensionAttribute15": "value15",
		}
		mask := []string{"extensionAttribute1", "extensionAttribute15"}

		changes := buildLDAPChanges(l, attrs, mask)
		if len(changes) != 2 {
			t.Fatalf("expected 2 changes, got %d", len(changes))
		}

		attrNames := make(map[string]bool)
		for _, c := range changes {
			attrNames[c.Modification.Type] = true
		}
		if !attrNames["extensionAttribute1"] {
			t.Error("expected extensionAttribute1 in changes")
		}
		if !attrNames["extensionAttribute15"] {
			t.Error("expected extensionAttribute15 in changes")
		}
	})

	t.Run("empty value deletes attribute", func(t *testing.T) {
		attrs := map[string]string{
			"first_name": "",
		}
		mask := []string{"first_name"}

		changes := buildLDAPChanges(l, attrs, mask)
		if len(changes) != 1 {
			t.Fatalf("expected 1 change, got %d", len(changes))
		}
		// Delete operation is 1 in go-ldap.
		if changes[0].Operation != 1 {
			t.Errorf("expected delete operation (1), got %d", changes[0].Operation)
		}
	})

	t.Run("missing attr in mask is skipped", func(t *testing.T) {
		attrs := map[string]string{
			"first_name": "Jane",
		}
		mask := []string{"first_name", "missing_attr"}

		changes := buildLDAPChanges(l, attrs, mask)
		if len(changes) != 1 {
			t.Fatalf("expected 1 change, got %d", len(changes))
		}
	})

	t.Run("mixed standard and extension", func(t *testing.T) {
		attrs := map[string]string{
			"first_name":          "Jane",
			"extensionAttribute5": "custom_value",
			"telephoneNumber":     "+1234567890",
		}
		mask := []string{"first_name", "extensionAttribute5", "telephoneNumber"}

		changes := buildLDAPChanges(l, attrs, mask)
		if len(changes) != 3 {
			t.Fatalf("expected 3 changes, got %d", len(changes))
		}

		attrNames := make(map[string]bool)
		for _, c := range changes {
			attrNames[c.Modification.Type] = true
		}
		if !attrNames["givenName"] {
			t.Error("expected givenName in changes")
		}
		if !attrNames["extensionAttribute5"] {
			t.Error("expected extensionAttribute5 in changes")
		}
		if !attrNames["telephoneNumber"] {
			t.Error("expected telephoneNumber in changes")
		}
	})
}
