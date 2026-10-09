package subscription

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/biologmder/vps-proxy-console/internal/model"
)

func TestPrivateInboundNotDistributed(t *testing.T) {
	s := model.State{Nodes: []model.Node{{ID: "n", Name: "Node", Domain: "node.example.com"}}, Inbounds: []model.Inbound{{ID: "v", NodeID: "n", Name: "VLESS", Protocol: "vless-tls", Port: 443, Domain: "node.example.com", Enabled: true}, {ID: "s", NodeID: "n", Name: "Landing", Protocol: "socks", Listen: "10.0.0.1", Port: 1080, Enabled: true}}, Assignments: []model.Assignment{{ID: "a1", PersonID: "p", InboundID: "v", Credential: "11111111-1111-4111-8111-111111111111"}, {ID: "a2", PersonID: "p", InboundID: "s", Credential: "secret"}}}
	p := model.Person{ID: "p", Name: "Alice"}
	entries := Entries(s, p)
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Link, "vless://") {
		t.Fatalf("entries=%+v", entries)
	}
	if strings.Contains(string(Raw(entries)), "1080") {
		t.Fatal("private inbound leaked")
	}
}
func TestTransportLinks(t *testing.T) {
	s := model.State{Nodes: []model.Node{{ID: "n", Name: "Node", Domain: "node.example.com"}}, Inbounds: []model.Inbound{
		{ID: "x", NodeID: "n", Name: "XHTTP", Protocol: "vless", Network: "xhttp", Security: "reality", Port: 443, Domain: "www.microsoft.com", RealityPublicKey: "pub", RealityShortID: "ab", Enabled: true},
		{ID: "s", NodeID: "n", Name: "SS2022", Protocol: "shadowsocks", SSMethod: "2022-blake3-aes-128-gcm", SSServerKey: "c2VydmVyLWtleS0xNmJ5dA==", Port: 8388, Enabled: true},
	}, Assignments: []model.Assignment{
		{ID: "a1", PersonID: "p", InboundID: "x", Credential: "11111111-1111-4111-8111-111111111111"},
		{ID: "a2", PersonID: "p", InboundID: "s", Credential: "dXNlci1rZXktMTZieXRlcw=="},
	}}
	entries := Entries(s, model.Person{ID: "p", Name: "Alice"})
	if len(entries) != 2 {
		t.Fatalf("entries=%+v", entries)
	}
	if l := entries[0].Link; !strings.Contains(l, "type=xhttp") || !strings.Contains(l, "security=reality") || !strings.Contains(l, "path=%2Fxhttp") || entries[0].Proxy != nil {
		t.Fatalf("xhttp entry: %s %+v", l, entries[0].Proxy)
	}
	if l := entries[1].Link; !strings.HasPrefix(l, "ss://2022-blake3-aes-128-gcm:c2VydmVyLWtleS0xNmJ5dA%3D%3D:dXNlci1rZXktMTZieXRlcw%3D%3D@") {
		t.Fatalf("ss2022 link: %s", l)
	}
	if entries[1].Proxy["password"] != "c2VydmVyLWtleS0xNmJ5dA==:dXNlci1rZXktMTZieXRlcw==" {
		t.Fatalf("ss2022 mihomo password: %v", entries[1].Proxy["password"])
	}
}
func TestMihomoConfig(t *testing.T) {
	bin := os.Getenv("MIHOMO_BIN")
	if bin == "" {
		t.Skip("set MIHOMO_BIN to run integration test")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := model.State{Nodes: []model.Node{{ID: "n", Name: "Node", Domain: "node.example.com"}}, Inbounds: []model.Inbound{
		{ID: "v", NodeID: "n", Name: "VLESS", Protocol: "vless-tls", Port: 443, Domain: "node.example.com", Enabled: true},
		{ID: "r", NodeID: "n", Name: "REALITY", Protocol: "vless-reality", Port: 1443, Domain: "www.microsoft.com", RealityPublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), RealityShortID: "abcd1234", Enabled: true},
		{ID: "tr", NodeID: "n", Name: "Trojan", Protocol: "trojan-tls", Port: 2443, Domain: "node.example.com", Enabled: true},
		{ID: "ss", NodeID: "n", Name: "SS", Protocol: "ss", Port: 3443, Enabled: true},
		{ID: "vm", NodeID: "n", Name: "VMess", Protocol: "vmess-ws-tls", Port: 8443, Domain: "node.example.com", Path: "/ws", Enabled: true},
		{ID: "g", NodeID: "n", Name: "gRPC", Protocol: "vless", Network: "grpc", Security: "tls", Port: 4443, Domain: "node.example.com", ServiceName: "svc", Enabled: true},
		{ID: "hu", NodeID: "n", Name: "HTTPUpgrade", Protocol: "vmess", Network: "httpupgrade", Security: "none", Port: 5443, Path: "/up", Enabled: true},
		{ID: "tw", NodeID: "n", Name: "TrojanWS", Protocol: "trojan", Network: "ws", Security: "tls", Port: 6443, Domain: "node.example.com", Path: "/tr", Enabled: true},
		{ID: "s22", NodeID: "n", Name: "SS2022", Protocol: "shadowsocks", SSMethod: "2022-blake3-aes-128-gcm", SSServerKey: "c2VydmVyLWtleS0xNmJ5dA==", Port: 7443, Enabled: true},
	}, Assignments: []model.Assignment{
		{ID: "a6", PersonID: "p", InboundID: "g", Credential: "44444444-4444-4444-8444-444444444444"},
		{ID: "a7", PersonID: "p", InboundID: "hu", Credential: "55555555-5555-4555-8555-555555555555"},
		{ID: "a8", PersonID: "p", InboundID: "tw", Credential: "trojan-password-456"},
		{ID: "a9", PersonID: "p", InboundID: "s22", Credential: "dXNlci1rZXktMTZieXRlcw=="},
		{ID: "a1", PersonID: "p", InboundID: "v", Credential: "11111111-1111-4111-8111-111111111111"},
		{ID: "a2", PersonID: "p", InboundID: "r", Credential: "22222222-2222-4222-8222-222222222222"},
		{ID: "a3", PersonID: "p", InboundID: "tr", Credential: "trojan-password-123"},
		{ID: "a4", PersonID: "p", InboundID: "ss", Credential: "ss-password-12345"},
		{ID: "a5", PersonID: "p", InboundID: "vm", Credential: "33333333-3333-4333-8333-333333333333"},
	}}
	b, err := Mihomo(Entries(s, model.Person{ID: "p", Name: "Alice"}))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-t", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("mihomo config: %v\n%s\n%s", err, b, out)
	}
}
