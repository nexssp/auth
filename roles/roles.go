// Package roles provides zero-boilerplate role-based service composition.
// Instead of a switch statement in every main.go, declare once and run.
//
// Usage:
//
//	roles.New().
//	    Add("gateway",  gateway.Setup).
//	    Add("pipeline", pipeline.Setup).
//	    Add("eval",     eval.Setup).
//	    AddAlias("all", "gateway", "pipeline", "eval").
//	    Run(app, cfg)
package roles

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
)

// SetupFn is any function that configures a nexss.App for a given role.
// Keep it generic — callers can use any signature via closure capture.
type SetupFn func()

// Registry maps role names to their setup functions.
type Registry struct {
	roles   map[string][]SetupFn
	aliases map[string][]string // alias → []role names
}

func New() *Registry {
	return &Registry{
		roles:   make(map[string][]SetupFn),
		aliases: make(map[string][]string),
	}
}

// Add registers one or more setup functions for a named role.
// Multiple calls to Add with the same name append (useful for composing).
func (r *Registry) Add(name string, fns ...SetupFn) *Registry {
	r.roles[name] = append(r.roles[name], fns...)
	return r
}

// AddAlias defines a composite role that runs multiple underlying roles.
//
//	AddAlias("all", "gateway", "pipeline", "eval")
func (r *Registry) AddAlias(alias string, roles ...string) *Registry {
	r.aliases[alias] = roles
	return r
}

// Run reads ROLE from the environment and executes the matching setup functions.
// Panics with a helpful message if the role is unknown — fail fast at boot.
func (r *Registry) Run(envKey ...string) {
	key := "ROLE"
	if len(envKey) > 0 && envKey[0] != "" {
		key = envKey[0]
	}

	role := os.Getenv(key)
	if role == "" {
		role = "all"
	}

	// Resolve alias
	if targets, ok := r.aliases[role]; ok {
		slog.Info("role_alias_resolved", "alias", role, "targets", strings.Join(targets, ","))
		for _, t := range targets {
			r.run(t)
		}
		return
	}

	r.run(role)
}

func (r *Registry) run(name string) {
	fns, ok := r.roles[name]
	if !ok {
		known := r.knownRoles()
		fmt.Fprintf(os.Stderr,
			"unknown ROLE=%q — available: %s\n",
			name, strings.Join(known, " | "),
		)
		os.Exit(1)
	}
	slog.Info("role_starting", "role", name)
	for _, fn := range fns {
		fn()
	}
}

func (r *Registry) knownRoles() []string {
	out := make([]string, 0, len(r.roles)+len(r.aliases))
	for k := range r.roles {
		out = append(out, k)
	}
	for k := range r.aliases {
		out = append(out, k+"(alias)")
	}
	sort.Strings(out)
	return out
}
