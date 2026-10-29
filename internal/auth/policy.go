// Package auth signs people in with OpenID Connect and decides what they
// may do. Permissions come from an access policy that maps the groups (or
// roles) in the identity provider's tokens, and optionally individual
// users, directly to Patchline permissions.
package auth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Permission is one thing a person may do in Patchline.
type Permission string

const (
	// FindingsRead opens the web UI and the read API.
	FindingsRead Permission = "findings.read"
	// FindingsAssign sets or clears a finding's assignee.
	FindingsAssign Permission = "findings.assign"
	// ExceptionsRequest asks for a risk acceptance or a due date extension.
	ExceptionsRequest Permission = "exceptions.request"
	// ExceptionsApprove approves or rejects other people's requests.
	ExceptionsApprove Permission = "exceptions.approve"
	// SettingsWebhooks views and changes the webhook token and secret.
	SettingsWebhooks Permission = "settings.webhooks"
	// AuditRead views the audit log.
	AuditRead Permission = "audit.read"

	// All grants every permission.
	All Permission = "*"
)

// Permissions lists every permission in display order.
var Permissions = []Permission{FindingsRead, FindingsAssign, ExceptionsRequest, ExceptionsApprove, SettingsWebhooks, AuditRead}

func known(p Permission) bool { return p == All || slices.Contains(Permissions, p) }

// Policy maps identities to permissions.
//
//	default: [findings.read]          # everyone who signs in
//	groups:
//	  sec-team: [findings.read, exceptions.approve]
//	users:
//	  alice@example.com: ["*"]        # by email or subject
type Policy struct {
	Default []Permission            `yaml:"default"`
	Groups  map[string][]Permission `yaml:"groups"`
	Users   map[string][]Permission `yaml:"users"`
}

// DefaultPolicy lets everyone who signs in read, and nothing else.
func DefaultPolicy() Policy {
	return Policy{Default: []Permission{FindingsRead}}
}

// LoadPolicy reads a policy file; an empty path returns DefaultPolicy.
func LoadPolicy(path string) (Policy, error) {
	if path == "" {
		return DefaultPolicy(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("access policy: %w", err)
	}
	p, err := ParsePolicy(data)
	if err != nil {
		return Policy{}, fmt.Errorf("access policy %s: %w", path, err)
	}
	return p, nil
}

// ParsePolicy decodes and validates a policy, rejecting unknown fields and
// permissions so typos fail loudly.
func ParsePolicy(data []byte) (Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return Policy{}, err
	}
	var errs []error
	check := func(where string, perms []Permission) {
		for _, perm := range perms {
			if !known(perm) {
				errs = append(errs, fmt.Errorf("%s: unknown permission %q", where, perm))
			}
		}
	}
	check("default", p.Default)
	for g, perms := range p.Groups {
		check("groups."+g, perms)
	}
	for u, perms := range p.Users {
		check("users."+u, perms)
	}
	if len(errs) > 0 {
		return Policy{}, errors.Join(errs...)
	}
	return p, nil
}

// Set is a resolved set of permissions.
type Set map[Permission]bool

// Has reports whether the set grants p.
func (s Set) Has(p Permission) bool { return s[All] || s[p] }

// List returns the granted permissions in display order.
func (s Set) List() []Permission {
	if s[All] {
		return slices.Clone(Permissions)
	}
	var out []Permission
	for _, p := range Permissions {
		if s[p] {
			out = append(out, p)
		}
	}
	return out
}

// For resolves the permissions of a person.
func (p Policy) For(subject, email string, groups []string) Set {
	s := Set{}
	add := func(perms []Permission) {
		for _, perm := range perms {
			s[perm] = true
		}
	}
	add(p.Default)
	for _, g := range groups {
		add(p.Groups[g])
	}
	add(p.Users[subject])
	if email != "" {
		add(p.Users[strings.ToLower(email)])
		add(p.Users[email])
	}
	return s
}

// Summary describes the policy for the startup log: which groups hold the
// permissions that change things.
func (p Policy) Summary() string {
	var parts []string
	for _, perm := range []Permission{ExceptionsApprove, SettingsWebhooks} {
		var who []string
		for g, perms := range p.Groups {
			if slices.Contains(perms, perm) || slices.Contains(perms, All) {
				who = append(who, g)
			}
		}
		for u, perms := range p.Users {
			if slices.Contains(perms, perm) || slices.Contains(perms, All) {
				who = append(who, u)
			}
		}
		sort.Strings(who)
		if len(who) == 0 {
			who = []string{"nobody"}
		}
		parts = append(parts, string(perm)+": "+strings.Join(who, ", "))
	}
	return strings.Join(parts, "; ")
}
