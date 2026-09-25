package subscription

import (
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
func TestMihomoConfig(t *testing.T) {
	bin := os.Getenv("MIHOMO_BIN")
	if bin == "" {
		t.Skip("set MIHOMO_BIN to run integration test")
	}
	s := model.State{Nodes: []model.Node{{ID: "n", Name: "Node", Domain: "node.example.com"}}, Inbounds: []model.Inbound{{ID: "v", NodeID: "n", Name: "VLESS", Protocol: "vless-tls", Port: 443, Domain: "node.example.com", Enabled: true}, {ID: "vm", NodeID: "n", Name: "VMess", Protocol: "vmess-ws-tls", Port: 8443, Domain: "node.example.com", Path: "/ws", Enabled: true}}, Assignments: []model.Assignment{{ID: "a1", PersonID: "p", InboundID: "v", Credential: "11111111-1111-4111-8111-111111111111"}, {ID: "a2", PersonID: "p", InboundID: "vm", Credential: "22222222-2222-4222-8222-222222222222"}}}
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
