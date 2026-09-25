package store

import (
	"path/filepath"
	"testing"

	"github.com/biologmder/vps-proxy-console/internal/model"
)

func TestMonotonicUsageAndDeletedAssignment(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	for _, v := range []struct {
		kind, id string
		value    any
	}{
		{"nodes", "n1", model.Node{ID: "n1", Name: "Node", Domain: "node.example.com"}},
		{"people", "p1", model.Person{ID: "p1", Name: "Alice", QuotaBytes: 1000}},
		{"inbounds", "i1", model.Inbound{ID: "i1", NodeID: "n1", Protocol: "vless-tls", Port: 443, Domain: "node.example.com", Enabled: true}},
		{"assignments", "a1", model.Assignment{ID: "a1", PersonID: "p1", InboundID: "i1", Credential: "uuid"}},
	} {
		if err := s.Upsert(v.kind, v.id, v.value, true); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []int64{100, 100, 150} {
		if err := s.Report("n1", model.Report{Totals: map[string]int64{"a1": n}}); err != nil {
			t.Fatal(err)
		}
	}
	st, err := s.State()
	if err != nil {
		t.Fatal(err)
	}
	if st.People[0].UsedBytes != 150 {
		t.Fatalf("usage=%d", st.People[0].UsedBytes)
	}
	if err := s.Delete("assignments", "a1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Report("n1", model.Report{Totals: map[string]int64{"a1": 200}}); err != nil {
		t.Fatal(err)
	}
	st, err = s.State()
	if err != nil {
		t.Fatal(err)
	}
	if st.People[0].UsedBytes != 200 {
		t.Fatalf("deleted assignment usage=%d", st.People[0].UsedBytes)
	}
}
