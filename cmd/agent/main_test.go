package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/biologmder/vps-proxy-console/internal/model"
)

func TestMain(m *testing.M) {
	if os.Getenv("VPC_TEST_XRAY") == "1" {
		os.Exit(fakeXray())
	}
	os.Exit(m.Run())
}
func fakeXray() int {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "api" {
		_, _ = os.Stdout.WriteString(`{"stat":[]}`)
		return 0
	}
	if len(args) < 3 || args[0] != "run" {
		return 2
	}
	b, err := os.ReadFile(args[len(args)-1])
	if err != nil {
		return 2
	}
	if strings.Contains(string(b), "bad-test") && args[1] == "-test" {
		return 1
	}
	if strings.Contains(string(b), "bad-run") && args[1] != "-test" {
		return 1
	}
	if args[1] == "-test" {
		return 0
	}
	time.Sleep(30 * time.Second)
	return 0
}

func TestApplyRollback(t *testing.T) {
	t.Setenv("VPC_TEST_XRAY", "1")
	a := &Agent{dir: t.TempDir(), xray: os.Args[0]}
	if err := a.apply([]byte(`{"version":"good1"}`)); err != nil {
		t.Fatal(err)
	}
	defer a.stopProcess()
	if err := a.apply([]byte(`{"version":"bad-test"}`)); err == nil {
		t.Fatal("invalid config accepted")
	}
	b, _ := os.ReadFile(filepath.Join(a.dir, "active.json"))
	if !strings.Contains(string(b), "good1") {
		t.Fatal("invalid config replaced active config")
	}
	if err := a.apply([]byte(`{"version":"bad-run"}`)); err == nil {
		t.Fatal("failed start accepted")
	}
	b, _ = os.ReadFile(filepath.Join(a.dir, "active.json"))
	if !strings.Contains(string(b), "good1") {
		t.Fatal("rollback did not restore active config")
	}
	if a.proc == nil {
		t.Fatal("previous process not restarted")
	}
}

func TestOfflineReconnect(t *testing.T) {
	t.Setenv("VPC_TEST_XRAY", "1")
	a := &Agent{dir: t.TempDir(), xray: os.Args[0], nodeID: "n", token: "test", client: &http.Client{Timeout: time.Second}, allowed: map[string]bool{}, totals: map[string]int64{}}
	defer a.stopProcess()
	reports := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Node-ID") != "n" || r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", 401)
			return
		}
		if r.URL.Path == "/agent/v1/sync" {
			_ = json.NewEncoder(w).Encode(model.Desired{Revision: 3, Config: []byte(`{"version":"good"}`)})
			return
		}
		if r.URL.Path == "/agent/v1/report" {
			reports++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		http.NotFound(w, r)
	})
	server := httptest.NewServer(handler)
	a.panel = server.URL
	a.tick(t.Context())
	if a.proc == nil || reports != 1 {
		t.Fatalf("first sync failed, reports=%d", reports)
	}
	server.Close()
	a.tick(t.Context())
	if a.proc == nil {
		t.Fatal("offline sync stopped last valid process")
	}
	server = httptest.NewServer(handler)
	defer server.Close()
	a.panel = server.URL
	a.tick(t.Context())
	if reports != 2 || a.revision != 3 {
		t.Fatalf("reconnect failed, reports=%d revision=%d", reports, a.revision)
	}
}
