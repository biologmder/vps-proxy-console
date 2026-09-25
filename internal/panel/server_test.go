package panel

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/biologmder/vps-proxy-console/internal/store"
)

func TestAdminToSubscriptionFlow(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	s, err := New(st, "a-very-strong-password", "http://example.test", "")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	client := server.Client()
	post := func(path string, v any, cookie *http.Cookie) (int, map[string]any) {
		t.Helper()
		b, _ := json.Marshal(v)
		r, _ := http.NewRequest("POST", server.URL+path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body
	}
	status, _ := post("/api/v1/login", map[string]string{"password": "a-very-strong-password"}, nil)
	if status != 200 {
		t.Fatalf("login status %d", status)
	}
	// A fresh login response gives us the cookie; sessions are intentionally server-side.
	b, _ := json.Marshal(map[string]string{"password": "a-very-strong-password"})
	resp, err := client.Post(server.URL+"/api/v1/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	cookie := resp.Cookies()[0]
	resp.Body.Close()
	status, node := post("/api/v1/nodes", map[string]any{"name": "Entry", "domain": "entry.example.com", "private_ip": "10.0.0.2"}, cookie)
	if status != 201 {
		t.Fatalf("node status %d: %+v", status, node)
	}
	nodeID := node["item"].(map[string]any)["id"].(string)
	status, person := post("/api/v1/people", map[string]any{"name": "Alice", "quota_bytes": 1000000}, cookie)
	if status != 201 {
		t.Fatalf("person status %d: %+v", status, person)
	}
	personID := person["item"].(map[string]any)["id"].(string)
	token := person["token"].(string)
	status, in := post("/api/v1/inbounds", map[string]any{"node_id": nodeID, "name": "Primary", "protocol": "vless-tls", "port": 24443, "domain": "entry.example.com", "enabled": true}, cookie)
	if status != 201 {
		t.Fatalf("inbound status %d: %+v", status, in)
	}
	inID := in["item"].(map[string]any)["id"].(string)
	status, assignment := post("/api/v1/assignments", map[string]any{"person_id": personID, "inbound_id": inID}, cookie)
	if status != 201 {
		t.Fatalf("assignment status %d: %+v", status, assignment)
	}
	r, err := client.Get(server.URL + "/sub/" + token)
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	raw = buf.String()
	r.Body.Close()
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(decoded), "vless://") {
		t.Fatalf("raw subscription %s", decoded)
	}
	r, err = client.Get(server.URL + "/sub/" + token + "?format=mihomo")
	if err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	buf.ReadFrom(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || !strings.Contains(buf.String(), "type: vless") {
		t.Fatalf("mihomo: %d %s", r.StatusCode, buf.String())
	}
	status, rotation := post("/api/v1/people/"+personID+"/rotate", map[string]any{}, cookie)
	if status != 200 {
		t.Fatalf("rotate status %d", status)
	}
	r, err = client.Get(server.URL + "/sub/" + token)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 404 {
		t.Fatalf("old token status %d", r.StatusCode)
	}
	r, err = client.Get(server.URL + "/sub/" + rotation["token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("new token status %d", r.StatusCode)
	}
}
