package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/biologmder/vps-proxy-console/internal/model"
)

func fixture(t *testing.T) model.State {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := model.State{Revision: 7, Nodes: []model.Node{{ID: "n1", Name: "Entry", Domain: "node.example.com", PrivateIP: "10.0.0.2"}, {ID: "n2", Name: "Landing", Domain: "exit.example.com", PrivateIP: "10.0.0.3"}}, People: []model.Person{{ID: "p1", Name: "Alice", QuotaBytes: 1000}}}
	s.Inbounds = []model.Inbound{
		{ID: "i1", NodeID: "n1", Name: "VLESS", Protocol: "vless-tls", Port: 20001, Domain: "node.example.com", Enabled: true},
		{ID: "i2", NodeID: "n1", Name: "REALITY", Protocol: "vless-reality", Port: 20002, Domain: "www.microsoft.com", RealityDest: "www.microsoft.com:443", RealityPrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), RealityPublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), RealityShortID: "abcd1234", Enabled: true},
		{ID: "i3", NodeID: "n1", Name: "Trojan", Protocol: "trojan-tls", Port: 20003, Domain: "node.example.com", Enabled: true},
		{ID: "i4", NodeID: "n1", Name: "SS", Protocol: "ss", Port: 20004, SSServerKey: "server-password-12345", Enabled: true},
		{ID: "i5", NodeID: "n1", Name: "VMess", Protocol: "vmess-ws-tls", Port: 20005, Domain: "node.example.com", Path: "/ws", Enabled: true},
		{ID: "i6", NodeID: "n2", Name: "SOCKS", Protocol: "socks", Listen: "10.0.0.3", Port: 20006, ServiceUser: "relay", ServicePassword: "secret", Enabled: true},
		{ID: "i7", NodeID: "n2", Name: "HTTP", Protocol: "http", Listen: "10.0.0.3", Port: 20007, ServiceUser: "relay", ServicePassword: "secret", Enabled: true},
	}
	// Inbounds using the separate protocol/transport/security fields.
	s.Inbounds = append(s.Inbounds,
		model.Inbound{ID: "i8", NodeID: "n1", Name: "VLESS XHTTP REALITY", Protocol: "vless", Network: "xhttp", Security: "reality", Port: 20008, Domain: "www.microsoft.com", RealityDest: "www.microsoft.com:443", RealityPrivateKey: s.Inbounds[1].RealityPrivateKey, RealityPublicKey: s.Inbounds[1].RealityPublicKey, RealityShortID: "ab", Enabled: true},
		model.Inbound{ID: "i9", NodeID: "n1", Name: "VLESS gRPC TLS", Protocol: "vless", Network: "grpc", Security: "tls", Port: 20009, Domain: "node.example.com", ServiceName: "svc", Enabled: true},
		model.Inbound{ID: "ia", NodeID: "n1", Name: "VMess HTTPUpgrade", Protocol: "vmess", Network: "httpupgrade", Security: "none", Port: 20010, Path: "/up", Enabled: true},
		model.Inbound{ID: "ib", NodeID: "n1", Name: "Trojan WS TLS", Protocol: "trojan", Network: "ws", Security: "tls", Port: 20011, Domain: "node.example.com", Path: "/tr", Enabled: true},
		model.Inbound{ID: "ic", NodeID: "n1", Name: "SS2022", Protocol: "shadowsocks", SSMethod: "2022-blake3-aes-128-gcm", SSServerKey: "AAAAAAAAAAAAAAAAAAAAAA==", Port: 20012, Enabled: true},
	)
	uuidInbounds := map[string]bool{"1": true, "2": true, "5": true, "8": true, "9": true, "a": true}
	for _, i := range "1234589abc" {
		credential := "password-long-enough"
		if uuidInbounds[string(i)] {
			credential = "11111111-1111-4111-8111-111111111111"
		}
		if i == 'c' {
			credential = "BBBBBBBBBBBBBBBBBBBBBB=="
		}
		s.Assignments = append(s.Assignments, model.Assignment{ID: "a" + string(i), PersonID: "p1", InboundID: "i" + string(i), Credential: credential})
	}
	s.Outbounds = []model.Outbound{{ID: "o1", NodeID: "n1", Name: "Landing SOCKS", Protocol: "socks", LandingInboundID: "i6"}, {ID: "o2", NodeID: "n1", Name: "Landing HTTP", Protocol: "http", LandingInboundID: "i7"}}
	s.Rules = []model.Rule{{ID: "r1", NodeID: "n1", Position: 1, PersonID: "p1", Domains: []string{"domain:example.com"}, OutboundID: "o1"}, {ID: "r2", NodeID: "n1", Position: 2, CIDRs: []string{"10.0.0.0/8"}, OutboundID: "block"}}
	return s
}

func TestCompile(t *testing.T) {
	s := fixture(t)
	desired, err := Compile(s, "n1")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(desired.Config, &doc); err != nil {
		t.Fatal(err)
	}
	ins := doc["inbounds"].([]any)
	if len(ins) != 10 {
		t.Fatalf("got %d inbounds", len(ins))
	}
	for _, raw := range ins {
		in := raw.(map[string]any)
		switch in["tag"] {
		case "in-i4":
			users := in["settings"].(map[string]any)["users"].([]any)
			if users[0].(map[string]any)["method"] != "aes-256-gcm" {
				t.Fatal("Shadowsocks user missing per-user cipher")
			}
		case "in-ic":
			users := in["settings"].(map[string]any)["users"].([]any)
			if _, ok := users[0].(map[string]any)["method"]; ok {
				t.Fatal("Shadowsocks 2022 users must not carry a method")
			}
		case "in-i2":
			client := in["settings"].(map[string]any)["clients"].([]any)[0].(map[string]any)
			if client["flow"] != "xtls-rprx-vision" {
				t.Fatal("legacy REALITY inbound lost Vision flow")
			}
		case "in-i8":
			stream := in["streamSettings"].(map[string]any)
			if stream["network"] != "xhttp" || stream["security"] != "reality" {
				t.Fatalf("xhttp reality stream: %+v", stream)
			}
		}
	}
	rules := doc["routing"].(map[string]any)["rules"].([]any)
	if len(rules) != 3 {
		t.Fatalf("got %d rules", len(rules))
	}
	guard := rules[0].(map[string]any)
	if guard["outboundTag"] != "block" || guard["ip"].([]any)[0] != "geoip:private" {
		t.Fatalf("private network guard must be the first rule: %+v", guard)
	}
	first := rules[1].(map[string]any)
	if first["outboundTag"] != "out-o1" || len(first["user"].([]any)) != 10 {
		t.Fatalf("unexpected user routing: %+v", first)
	}
	if len(desired.TLSNames) != 1 || desired.TLSNames[0] != "node.example.com" {
		t.Fatalf("tls names: %+v", desired.TLSNames)
	}
}
func TestUnsupportedCombinationRejected(t *testing.T) {
	for _, in := range []model.Inbound{
		{ID: "x", NodeID: "n1", Name: "ws reality", Protocol: "vless", Network: "ws", Security: "reality", Port: 30001, Domain: "www.microsoft.com", Enabled: true},
		{ID: "x", NodeID: "n1", Name: "vision ws", Protocol: "vless", Network: "ws", Security: "tls", Flow: "xtls-rprx-vision", Port: 30001, Domain: "node.example.com", Enabled: true},
		{ID: "x", NodeID: "n1", Name: "plain trojan", Protocol: "trojan", Network: "tcp", Security: "none", Port: 30001, Enabled: true},
		{ID: "x", NodeID: "n1", Name: "bad ss key", Protocol: "shadowsocks", SSMethod: "2022-blake3-aes-256-gcm", SSServerKey: "short", Port: 30001, Enabled: true},
	} {
		s := fixture(t)
		s.Inbounds = append(s.Inbounds, in)
		if _, err := Compile(s, "n1"); err == nil {
			t.Fatalf("%s accepted", in.Name)
		}
	}
}
func TestPrivateLandingEnforced(t *testing.T) {
	s := fixture(t)
	s.Inbounds[5].Listen = "0.0.0.0"
	if _, err := Compile(s, "n2"); err == nil {
		t.Fatal("public SOCKS listener accepted")
	}
}
func TestInvalidRealityTarget(t *testing.T) {
	s := fixture(t)
	s.Inbounds[1].RealityDest = "d"
	if _, err := Compile(s, "n1"); err == nil {
		t.Fatal("invalid REALITY target accepted")
	}
}
func TestQuotaDisablesAllAssignments(t *testing.T) {
	s := fixture(t)
	s.People[0].UsedBytes = 1000
	d, err := Compile(s, "n1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(d.Config), "a-a1@local") {
		t.Fatal("quota-exhausted user still in config")
	}
}

func TestRealXrayConfig(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("set XRAY_BIN to run integration test")
	}
	s := fixture(t)
	d, err := Compile(s, "n1")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert, key := selfSigned(t)
	if err = os.WriteFile(filepath.Join(dir, "node.example.com.crt"), cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "node.example.com.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	b := strings.ReplaceAll(string(d.Config), "/data/certs/", filepath.ToSlash(dir)+"/")
	path := filepath.Join(dir, "config.json")
	if err = os.WriteFile(path, []byte(b), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "run", "-test", "-c", path).CombinedOutput()
	if err != nil {
		t.Fatalf("xray test: %v\n%s", err, out)
	}
	landing, err := Compile(s, "n2")
	if err != nil {
		t.Fatal(err)
	}
	landingPath := filepath.Join(dir, "landing.json")
	if err = os.WriteFile(landingPath, landing.Config, 0600); err != nil {
		t.Fatal(err)
	}
	out, err = exec.Command(bin, "run", "-test", "-c", landingPath).CombinedOutput()
	if err != nil {
		t.Fatalf("landing xray test: %v\n%s", err, out)
	}
}
func selfSigned(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"node.example.com"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
}
