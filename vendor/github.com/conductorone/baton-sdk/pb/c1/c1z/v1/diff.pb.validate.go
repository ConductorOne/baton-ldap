// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: c1/c1z/v1/diff.proto

package v1

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on ResourceDiff with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *ResourceDiff) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on ResourceDiff with the rules defined
// in the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in ResourceDiffMultiError, or
// nil if none found.
func (m *ResourceDiff) ValidateAll() error {
	return m.validate(true)
}

func (m *ResourceDiff) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	for idx, item := range m.GetCreated() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, ResourceDiffValidationError{
						field:  fmt.Sprintf("Created[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, ResourceDiffValidationError{
						field:  fmt.Sprintf("Created[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ResourceDiffValidationError{
					field:  fmt.Sprintf("Created[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	for idx, item := range m.GetDeleted() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, ResourceDiffValidationError{
						field:  fmt.Sprintf("Deleted[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, ResourceDiffValidationError{
						field:  fmt.Sprintf("Deleted[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ResourceDiffValidationError{
					field:  fmt.Sprintf("Deleted[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	for idx, item := range m.GetModified() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, ResourceDiffValidationError{
						field:  fmt.Sprintf("Modified[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, ResourceDiffValidationError{
						field:  fmt.Sprintf("Modified[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ResourceDiffValidationError{
					field:  fmt.Sprintf("Modified[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(errors) > 0 {
		return ResourceDiffMultiError(errors)
	}

	return nil
}

// ResourceDiffMultiError is an error wrapping multiple validation errors
// returned by ResourceDiff.ValidateAll() if the designated constraints aren't met.
type ResourceDiffMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ResourceDiffMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ResourceDiffMultiError) AllErrors() []error { return m }

// ResourceDiffValidationError is the validation error returned by
// ResourceDiff.Validate if the designated constraints aren't met.
type ResourceDiffValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ResourceDiffValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ResourceDiffValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ResourceDiffValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ResourceDiffValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ResourceDiffValidationError) ErrorName() string { return "ResourceDiffValidationError" }

// Error satisfies the builtin error interface
func (e ResourceDiffValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sResourceDiff.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ResourceDiffValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ResourceDiffValidationError{}

// Validate checks the field values on EntitlementDiff with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *EntitlementDiff) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on EntitlementDiff with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// EntitlementDiffMultiError, or nil if none found.
func (m *EntitlementDiff) ValidateAll() error {
	return m.validate(true)
}

func (m *EntitlementDiff) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	for idx, item := range m.GetCreated() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, EntitlementDiffValidationError{
						field:  fmt.Sprintf("Created[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, EntitlementDiffValidationError{
						field:  fmt.Sprintf("Created[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return EntitlementDiffValidationError{
					field:  fmt.Sprintf("Created[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	for idx, item := range m.GetDeleted() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, EntitlementDiffValidationError{
						field:  fmt.Sprintf("Deleted[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, EntitlementDiffValidationError{
						field:  fmt.Sprintf("Deleted[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return EntitlementDiffValidationError{
					field:  fmt.Sprintf("Deleted[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	for idx, item := range m.GetModified() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, EntitlementDiffValidationError{
						field:  fmt.Sprintf("Modified[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, EntitlementDiffValidationError{
						field:  fmt.Sprintf("Modified[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return EntitlementDiffValidationError{
					field:  fmt.Sprintf("Modified[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(errors) > 0 {
		return EntitlementDiffMultiError(errors)
	}

	return nil
}

// EntitlementDiffMultiError is an error wrapping multiple validation errors
// returned by EntitlementDiff.ValidateAll() if the designated constraints
// aren't met.
type EntitlementDiffMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m EntitlementDiffMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m EntitlementDiffMultiError) AllErrors() []error { return m }

// EntitlementDiffValidationError is the validation error returned by
// EntitlementDiff.Validate if the designated constraints aren't met.
type EntitlementDiffValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e EntitlementDiffValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e EntitlementDiffValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e EntitlementDiffValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e EntitlementDiffValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e EntitlementDiffValidationError) ErrorName() string { return "EntitlementDiffValidationError" }

// Error satisfies the builtin error interface
func (e EntitlementDiffValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sEntitlementDiff.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = EntitlementDiffValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = EntitlementDiffValidationError{}

// Validate checks the field values on GrantDiff with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *GrantDiff) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on GrantDiff with the rules defined in
// the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in GrantDiffMultiError, or nil
// if none found.
func (m *GrantDiff) ValidateAll() error {
	return m.validate(true)
}

func (m *GrantDiff) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	for idx, item := range m.GetCreated() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, GrantDiffValidationError{
						field:  fmt.Sprintf("Created[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, GrantDiffValidationError{
						field:  fmt.Sprintf("Created[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return GrantDiffValidationError{
					field:  fmt.Sprintf("Created[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	for idx, item := range m.GetDeleted() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, GrantDiffValidationError{
						field:  fmt.Sprintf("Deleted[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, GrantDiffValidationError{
						field:  fmt.Sprintf("Deleted[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return GrantDiffValidationError{
					field:  fmt.Sprintf("Deleted[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	for idx, item := range m.GetModified() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, GrantDiffValidationError{
						field:  fmt.Sprintf("Modified[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, GrantDiffValidationError{
						field:  fmt.Sprintf("Modified[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return GrantDiffValidationError{
					field:  fmt.Sprintf("Modified[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(errors) > 0 {
		return GrantDiffMultiError(errors)
	}

	return nil
}

// GrantDiffMultiError is an error wrapping multiple validation errors returned
// by GrantDiff.ValidateAll() if the designated constraints aren't met.
type GrantDiffMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m GrantDiffMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m GrantDiffMultiError) AllErrors() []error { return m }

// GrantDiffValidationError is the validation error returned by
// GrantDiff.Validate if the designated constraints aren't met.
type GrantDiffValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e GrantDiffValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e GrantDiffValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e GrantDiffValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e GrantDiffValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e GrantDiffValidationError) ErrorName() string { return "GrantDiffValidationError" }

// Error satisfies the builtin error interface
func (e GrantDiffValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sGrantDiff.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = GrantDiffValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = GrantDiffValidationError{}

// Validate checks the field values on C1ZDiffOutput with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *C1ZDiffOutput) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on C1ZDiffOutput with the rules defined
// in the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in C1ZDiffOutputMultiError, or
// nil if none found.
func (m *C1ZDiffOutput) ValidateAll() error {
	return m.validate(true)
}

func (m *C1ZDiffOutput) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if all {
		switch v := interface{}(m.GetResources()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, C1ZDiffOutputValidationError{
					field:  "Resources",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, C1ZDiffOutputValidationError{
					field:  "Resources",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetResources()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return C1ZDiffOutputValidationError{
				field:  "Resources",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetEntitlements()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, C1ZDiffOutputValidationError{
					field:  "Entitlements",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, C1ZDiffOutputValidationError{
					field:  "Entitlements",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetEntitlements()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return C1ZDiffOutputValidationError{
				field:  "Entitlements",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetGrants()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, C1ZDiffOutputValidationError{
					field:  "Grants",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, C1ZDiffOutputValidationError{
					field:  "Grants",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetGrants()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return C1ZDiffOutputValidationError{
				field:  "Grants",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return C1ZDiffOutputMultiError(errors)
	}

	return nil
}

// C1ZDiffOutputMultiError is an error wrapping multiple validation errors
// returned by C1ZDiffOutput.ValidateAll() if the designated constraints
// aren't met.
type C1ZDiffOutputMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m C1ZDiffOutputMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m C1ZDiffOutputMultiError) AllErrors() []error { return m }

// C1ZDiffOutputValidationError is the validation error returned by
// C1ZDiffOutput.Validate if the designated constraints aren't met.
type C1ZDiffOutputValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e C1ZDiffOutputValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e C1ZDiffOutputValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e C1ZDiffOutputValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e C1ZDiffOutputValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e C1ZDiffOutputValidationError) ErrorName() string { return "C1ZDiffOutputValidationError" }

// Error satisfies the builtin error interface
func (e C1ZDiffOutputValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sC1ZDiffOutput.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = C1ZDiffOutputValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = C1ZDiffOutputValidationError{}
