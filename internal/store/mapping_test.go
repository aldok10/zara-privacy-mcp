package store

import (
	"testing"
)

func newTestStore(t *testing.T) *MappingStore {
	t.Helper()
	path := t.TempDir() + "/test.db"
	ms, err := NewMappingStore(path, []byte("test-key-32-bytes-long-minimum!!"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ms.Close() })
	return ms
}

func TestGetOrCreate(t *testing.T) {
	tests := []struct {
		name     string
		original string
		mtype    string
	}{
		{name: "email", original: "test@example.com", mtype: "Email"},
		{name: "api key", original: "sk-proj-abc123", mtype: "API Key"},
		{name: "phone", original: "+6281234567890", mtype: "Phone"},
	}

	ms := newTestStore(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := ms.GetOrCreate(tt.original, tt.mtype)
			if m.Placeholder == "" {
				t.Error("expected non-empty placeholder")
			}
			if m.Original != tt.original {
				t.Errorf("original = %q; want %q", m.Original, tt.original)
			}

			m2 := ms.GetOrCreate(tt.original, tt.mtype)
			if m2.Placeholder != m.Placeholder {
				t.Errorf("not idempotent: %q != %q", m2.Placeholder, m.Placeholder)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	ms := newTestStore(t)

	m := ms.GetOrCreate("secret@email.com", "Email")

	tests := []struct {
		name        string
		placeholder string
		wantFound   bool
	}{
		{name: "existing", placeholder: m.Placeholder, wantFound: true},
		{name: "non-existing", placeholder: "[UNKNOWN_99]", wantFound: false},
		{name: "empty", placeholder: "", wantFound: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, found := ms.Lookup(tt.placeholder)
			if found != tt.wantFound {
				t.Errorf("Lookup(%q) found = %v; want %v", tt.placeholder, found, tt.wantFound)
			}
		})
	}
}

func TestStats(t *testing.T) {
	ms := newTestStore(t)

	ms.GetOrCreate("a@b.com", "Email")
	ms.GetOrCreate("sk-abc", "API Key")
	ms.GetOrCreate("c@d.com", "Email")

	stats := ms.Stats()
	if stats["total_mappings"] != 3 {
		t.Errorf("total = %d; want 3", stats["total_mappings"])
	}
	if stats["type_Email"] != 2 {
		t.Errorf("type_Email = %d; want 2", stats["type_Email"])
	}
}

func TestSnapshot_Roundtrip(t *testing.T) {
	ms := newTestStore(t)
	ms.GetOrCreate("original-value", "Token")

	snap, err := ms.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap == "" {
		t.Fatal("expected non-empty snapshot")
	}

	ms2 := newTestStore(t)
	if err := ms2.RestoreFromSnapshot(snap); err != nil {
		t.Fatal(err)
	}

	stats := ms2.Stats()
	if stats["total_mappings"] != 1 {
		t.Errorf("restored total = %d; want 1", stats["total_mappings"])
	}
}
