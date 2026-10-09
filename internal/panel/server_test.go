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
	s, err := New(st, "a-very-strong-password", "https://panel.example.test:8443", "")
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
	if node["subscription_url"] != "" {
		t.Fatal("node token exposed as a subscription URL")
	}
	nodeID := node["item"].(map[string]any)["id"].(string)
	deploy := node["deploy_command"].(string)
	for _, expected := range []string{"PANEL_URL=https://panel.example.test:8443", "NODE_ID=" + nodeID, "NODE_TOKEN=" + node["token"].(string), "git clone https://github.com/biologmder/vps-proxy-console.git", "docker compose -f docker-compose.agent.yml pull agent", "docker compose -f docker-compose.agent.yml up -d"} {
		if !strings.Contains(deploy, expected) {
			t.Fatalf("deploy command missing %q", expected)
		}
	}
	if !st.CheckSecret("nodes", nodeID, node["token"].(string)) {
		t.Fatal("new node token invalid")
	}
	status, person := post("/api/v1/people", map[string]any{"name": "Alice", "quota_bytes": 1000000}, cookie)
	if status != 201 {
		t.Fatalf("person status %d: %+v", status, person)
	}
	personID := person["item"].(map[string]any)["id"].(string)
	token := person["token"].(string)
	if !strings.HasPrefix(person["subscription_url"].(string), "https://panel.example.test:8443/sub/") {
		t.Fatal("subscription URL lost the panel port")
	}
	status, in := post("/api/v1/inbounds", map[string]any{"node_id": nodeID, "name": "Primary", "protocol": "vless-tls", "port": 24443, "domain": "entry.example.com", "enabled": true}, cookie)
	if status != 201 {
		t.Fatalf("inbound status %d: %+v", status, in)
	}
	inID := in["item"].(map[string]any)["id"].(string)
	status, assignment := post("/api/v1/assignments", map[string]any{"person_id": personID, "inbound_id": inID}, cookie)
	if status != 201 {
		t.Fatalf("assignment status %d: %+v", status, assignment)
	}
	if in["item"].(map[string]any)["protocol"] != "vless" || in["item"].(map[string]any)["security"] != "tls" {
		t.Fatalf("legacy protocol not normalized: %+v", in["item"])
	}
	status, ss := post("/api/v1/inbounds", map[string]any{"node_id": nodeID, "name": "SS2022", "protocol": "shadowsocks", "ss_method": "2022-blake3-aes-256-gcm", "port": 24444, "enabled": true}, cookie)
	if status != 201 {
		t.Fatalf("ss2022 inbound status %d: %+v", status, ss)
	}
	if key, _ := base64.StdEncoding.DecodeString(ss["item"].(map[string]any)["ss_server_key"].(string)); len(key) != 32 {
		t.Fatalf("ss2022 server key has %d bytes", len(key))
	}
	status, ssAssignment := post("/api/v1/assignments", map[string]any{"person_id": personID, "inbound_id": ss["item"].(map[string]any)["id"]}, cookie)
	if status != 201 {
		t.Fatalf("ss2022 assignment status %d: %+v", status, ssAssignment)
	}
	if key, _ := base64.StdEncoding.DecodeString(ssAssignment["item"].(map[string]any)["credential"].(string)); len(key) != 32 {
		t.Fatalf("ss2022 user key has %d bytes", len(key))
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
	status, rotatedNode := post("/api/v1/nodes/"+nodeID+"/rotate", map[string]any{}, cookie)
	if status != 200 {
		t.Fatalf("node rotation status %d", status)
	}
	if st.CheckSecret("nodes", nodeID, node["token"].(string)) {
		t.Fatal("old node token still valid")
	}
	if !st.CheckSecret("nodes", nodeID, rotatedNode["token"].(string)) {
		t.Fatal("rotated node token invalid")
	}
	if !strings.Contains(rotatedNode["deploy_command"].(string), "NODE_TOKEN="+rotatedNode["token"].(string)) {
		t.Fatal("rotated command missing new token")
	}
}

func TestLoginRateLimitPerForwardedClient(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	s, err := New(st, "a-very-strong-password", "https://panel.example.test:8443", "")
	if err != nil {
		t.Fatal(err)
	}
	s.TrustProxy = true
	h := s.Handler()
	login := func(client, password string) int {
		b, _ := json.Marshal(map[string]string{"password": password})
		r := httptest.NewRequest("POST", "/api/v1/login", bytes.NewReader(b))
		r.RemoteAddr = "172.18.0.5:40000" // every request arrives from the Caddy container
		r.Header.Set("X-Forwarded-For", client)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 8; i++ {
		login("198.51.100.7", "wrong-password")
	}
	if code := login("198.51.100.7", "wrong-password"); code != 429 {
		t.Fatalf("attacker not limited: %d", code)
	}
	if code := login("203.0.113.9", "a-very-strong-password"); code != 200 {
		t.Fatalf("admin locked out by another client's failures: %d", code)
	}
}
