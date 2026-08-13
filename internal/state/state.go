// Package state is the local ledger of resources tmt has created, so a `down`
// can find and destroy them by name without the operator remembering the exact
// `up` command. It lives at ~/.tmt/state.json (override with TMT_HOME).
//
// Credentials are never persisted: RedactedCommand strips -ak/-sk/-st before a
// command is recorded, and the file is written 0600.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Resource is one AWS resource created for an Entry. Backend-specific fields
// are omitted when empty.
type Resource struct {
	Region   string `json:"region"`
	APIID    string `json:"api_id,omitempty"`   // apigateway
	APIName  string `json:"api_name,omitempty"` // apigateway
	Function string `json:"function,omitempty"` // jump
	Role     string `json:"role,omitempty"`     // jump
}

// Entry is one tracked `up` invocation.
type Entry struct {
	Name      string     `json:"name"`
	Backend   string     `json:"backend"` // "apigateway" | "jump"
	Target    string     `json:"target,omitempty"`
	Regions   []string   `json:"regions"`
	Command   string     `json:"command"` // credentials already stripped
	CreatedAt time.Time  `json:"created_at"`
	Resources []Resource `json:"resources"`
}

// Store is the whole ledger.
type Store struct {
	Entries []Entry `json:"entries"`
}

func baseDir() string {
	if d := os.Getenv("TMT_HOME"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".tmt" // ponytail: cwd fallback if HOME is unresolved; rare.
	}
	return filepath.Join(home, ".tmt")
}

// Path is the ledger file location, for display in messages.
func Path() string { return filepath.Join(baseDir(), "state.json") }

// Load reads the ledger. A missing file is an empty store, not an error.
func Load() (*Store, error) {
	data, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			return &Store{}, nil
		}
		return nil, fmt.Errorf("reading ledger: %w", err)
	}
	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing ledger %s: %w", Path(), err)
	}
	return &s, nil
}

// Save writes the ledger atomically (temp + rename), dir 0700, file 0600.
// ponytail: no lock; single-user CLI. Add flock if this ever goes concurrent.
func (s *Store) Save() error {
	dir := baseDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "state-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, Path())
}

// Add appends an entry, rejecting a duplicate name so a tracked resource is
// never silently clobbered.
func (s *Store) Add(e Entry) error {
	if _, ok := s.Get(e.Name); ok {
		return fmt.Errorf("a resource named %q already exists in the ledger", e.Name)
	}
	s.Entries = append(s.Entries, e)
	return nil
}

// Get returns the entry with the given name.
func (s *Store) Get(name string) (Entry, bool) {
	for _, e := range s.Entries {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}

// Remove drops the entry with the given name, reporting whether it existed.
func (s *Store) Remove(name string) bool {
	for i, e := range s.Entries {
		if e.Name == name {
			s.Entries = append(s.Entries[:i], s.Entries[i+1:]...)
			return true
		}
	}
	return false
}

// RemoveMatching drops the first entry matching a legacy (nameless) down, so
// the ledger stays consistent when the operator tears down by -t/-regions.
// apigateway matches on target; jump matches on the exact region set.
func (s *Store) RemoveMatching(backend, target string, regions []string) bool {
	for i, e := range s.Entries {
		if e.Backend != backend {
			continue
		}
		if backend == "apigateway" && e.Target == target {
			s.Entries = append(s.Entries[:i], s.Entries[i+1:]...)
			return true
		}
		if backend == "jump" && sameSet(e.Regions, regions) {
			s.Entries = append(s.Entries[:i], s.Entries[i+1:]...)
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		if !seen[x] {
			return false
		}
	}
	return true
}

// credFlags are the credential flag names (sans dashes) stripped from any
// command before it is recorded.
var credFlags = map[string]bool{"ak": true, "sk": true, "st": true}

// isCredFlag reports whether a is a credential flag, tolerating one or two
// leading dashes (Go's flag package accepts both).
func isCredFlag(a string) bool {
	return credFlags[strings.TrimLeft(a, "-")]
}

// RedactedCommand renders args as a runnable-looking command with AWS
// credential flags (and their values) removed, so secrets never hit disk.
// It handles "-ak VALUE", "-ak=VALUE", and the "--ak" double-dash variants.
func RedactedCommand(args []string) string {
	out := []string{"tmt"}
	skipValue := false
	for _, a := range args[1:] { // args[0] is the binary path
		if skipValue {
			skipValue = false
			continue
		}
		if i := strings.IndexByte(a, '='); i > 0 && isCredFlag(a[:i]) {
			continue // -ak=VALUE
		}
		if isCredFlag(a) {
			skipValue = true // -ak VALUE
			continue
		}
		out = append(out, a)
	}
	return strings.Join(out, " ")
}
