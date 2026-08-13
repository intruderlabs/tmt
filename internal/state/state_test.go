package state

import (
	"strings"
	"testing"
)

// useTempHome points the ledger at a throwaway dir via TMT_HOME.
func useTempHome(t *testing.T) {
	t.Setenv("TMT_HOME", t.TempDir())
}

func TestRoundTrip_AddSaveLoadGetRemove(t *testing.T) {
	useTempHome(t)

	s, err := Load()
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	if len(s.Entries) != 0 {
		t.Fatalf("expected empty store, got %d", len(s.Entries))
	}

	e := Entry{Name: "web", Backend: "apigateway", Target: "https://ex.com", Regions: []string{"us-east-1"}}
	if err := s.Add(e); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, ok := reloaded.Get("web")
	if !ok || got.Target != "https://ex.com" {
		t.Fatalf("Get after reload = %+v, ok=%v", got, ok)
	}

	if !reloaded.Remove("web") {
		t.Fatal("Remove returned false")
	}
	if _, ok := reloaded.Get("web"); ok {
		t.Fatal("entry still present after Remove")
	}
}

func TestAdd_RejectsDuplicateName(t *testing.T) {
	useTempHome(t)
	s := &Store{}
	if err := s.Add(Entry{Name: "dup"}); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := s.Add(Entry{Name: "dup"}); err == nil {
		t.Fatal("expected duplicate-name error")
	}
}

func TestRemoveMatching(t *testing.T) {
	s := &Store{Entries: []Entry{
		{Name: "a", Backend: "apigateway", Target: "https://ex.com"},
		{Name: "b", Backend: "jump", Regions: []string{"us-east-1", "sa-east-1"}},
	}}
	if !s.RemoveMatching("apigateway", "https://ex.com", nil) {
		t.Fatal("apigateway match failed")
	}
	// order-independent region set match
	if !s.RemoveMatching("jump", "", []string{"sa-east-1", "us-east-1"}) {
		t.Fatal("jump region-set match failed")
	}
	if len(s.Entries) != 0 {
		t.Fatalf("expected all removed, got %d", len(s.Entries))
	}
}

func TestRedactedCommand_StripsCredentials(t *testing.T) {
	// "-ak VALUE", "-sk=VALUE", and "--st VALUE" (double dash) must all be
	// removed, values gone.
	args := []string{"/path/to/tmt", "up", "-jump", "-regions", "us-east-1",
		"-ak", "AKIASECRET", "-sk=wJalrSECRET", "--st", "TOKEN", "-n", "scan"}
	got := RedactedCommand(args)
	want := "tmt up -jump -regions us-east-1 -n scan"
	if got != want {
		t.Fatalf("RedactedCommand = %q, want %q", got, want)
	}
	for _, secret := range []string{"AKIASECRET", "wJalrSECRET", "TOKEN"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q leaked into %q", secret, got)
		}
	}
}
