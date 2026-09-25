package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/biologmder/vps-proxy-console/internal/model"
)

func UserEmail(a model.Assignment) string { return "a-" + a.ID + "@local" }

func Compile(s model.State, nodeID string) (model.Desired, error) {
	var node *model.Node
	for i := range s.Nodes {
		if s.Nodes[i].ID == nodeID {
			node = &s.Nodes[i]
			break
		}
	}
	if node == nil {
		return model.Desired{}, errors.New("node not found")
	}
	people := map[string]model.Person{}
	for _, p := range s.People {
		people[p.ID] = p
	}
	assigned := map[string][]model.Assignment{}
	for _, a := range s.Assignments {
		assigned[a.InboundID] = append(assigned[a.InboundID], a)
	}
	inboundByID := map[string]model.Inbound{}
	for _, in := range s.Inbounds {
		inboundByID[in.ID] = in
	}
	var inbounds []any
	var tlsNames []string
	portSeen := map[int]bool{80: true, 10085: true}
	for _, in := range s.Inbounds {
		if in.NodeID != nodeID || !in.Enabled {
			continue
		}
		if in.Port < 1 || in.Port > 65535 || portSeen[in.Port] {
			return model.Desired{}, fmt.Errorf("invalid/duplicate port %d", in.Port)
		}
		portSeen[in.Port] = true
		cfg := map[string]any{"tag": "in-" + in.ID, "port": in.Port, "listen": in.Listen}
		if cfg["listen"] == "" {
			cfg["listen"] = "0.0.0.0"
		}
		clients := []any{}
		for _, a := range assigned[in.ID] {
			p, ok := people[a.PersonID]
			if !ok || p.Disabled || (p.QuotaBytes > 0 && p.UsedBytes >= p.QuotaBytes) || (p.ExpiresAt != nil && !p.ExpiresAt.IsZero() && p.ExpiresAt.Before(now())) {
				continue
			}
			client := map[string]any{"email": UserEmail(a)}
			switch in.Protocol {
			case "vless-tls", "vless-reality", "vmess-ws-tls":
				client["id"] = a.Credential
			case "trojan-tls", "ss":
				client["password"] = a.Credential
			}
			if in.Protocol == "vless-reality" {
				client["flow"] = "xtls-rprx-vision"
			}
			if in.Protocol == "vmess-ws-tls" {
				client["alterId"] = 0
			}
			clients = append(clients, client)
		}
		switch in.Protocol {
		case "vless-tls", "vless-reality":
			cfg["protocol"] = "vless"
			cfg["settings"] = map[string]any{"clients": clients, "decryption": "none"}
		case "trojan-tls":
			cfg["protocol"] = "trojan"
			cfg["settings"] = map[string]any{"clients": clients}
		case "vmess-ws-tls":
			cfg["protocol"] = "vmess"
			cfg["settings"] = map[string]any{"clients": clients}
		case "ss":
			if in.SSServerKey == "" {
				return model.Desired{}, fmt.Errorf("ss inbound %s missing server password", in.ID)
			}
			cfg["protocol"] = "shadowsocks"
			cfg["settings"] = map[string]any{"network": "tcp,udp", "method": "aes-256-gcm", "password": in.SSServerKey, "users": clients}
		case "socks", "http":
			if node.PrivateIP == "" || net.ParseIP(in.Listen) == nil || in.Listen != node.PrivateIP {
				return model.Desired{}, fmt.Errorf("%s must listen on node private IP", in.Protocol)
			}
			if in.ServiceUser == "" || in.ServicePassword == "" {
				return model.Desired{}, fmt.Errorf("%s requires service credentials", in.Protocol)
			}
			cfg["protocol"] = in.Protocol
			settings := map[string]any{"users": []any{map[string]any{"user": in.ServiceUser, "pass": in.ServicePassword}}}
			if in.Protocol == "socks" {
				settings["auth"] = "password"
				settings["udp"] = false
			}
			cfg["settings"] = settings
		default:
			return model.Desired{}, fmt.Errorf("unsupported protocol %s", in.Protocol)
		}
		if strings.HasSuffix(in.Protocol, "-tls") || in.Protocol == "vless-reality" {
			if !validDomain(in.Domain) {
				return model.Desired{}, fmt.Errorf("invalid domain %q", in.Domain)
			}
			stream := map[string]any{"network": "tcp"}
			if in.Protocol == "vmess-ws-tls" {
				path := in.Path
				if path == "" {
					path = "/ws"
				}
				if !strings.HasPrefix(path, "/") {
					return model.Desired{}, errors.New("websocket path must start with /")
				}
				stream["network"] = "ws"
				stream["wsSettings"] = map[string]any{"path": path, "headers": map[string]string{"Host": in.Domain}}
			}
			if in.Protocol == "vless-reality" {
				if in.RealityDest == "" || in.RealityPrivateKey == "" || in.RealityShortID == "" {
					return model.Desired{}, errors.New("REALITY destination/key/short ID required")
				}
				stream["security"] = "reality"
				stream["realitySettings"] = map[string]any{"show": false, "dest": in.RealityDest, "xver": 0, "serverNames": []string{in.Domain}, "privateKey": in.RealityPrivateKey, "shortIds": []string{in.RealityShortID}}
			} else {
				stream["security"] = "tls"
				stream["tlsSettings"] = map[string]any{"certificates": []any{map[string]string{"certificateFile": "/data/certs/" + in.Domain + ".crt", "keyFile": "/data/certs/" + in.Domain + ".key"}}}
				tlsNames = append(tlsNames, in.Domain)
			}
			cfg["streamSettings"] = stream
		}
		if in.Protocol != "socks" && in.Protocol != "http" {
			cfg["sniffing"] = map[string]any{"enabled": true, "destOverride": []string{"http", "tls"}, "routeOnly": true}
		}
		inbounds = append(inbounds, cfg)
	}
	outbounds := []any{map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "block", "protocol": "blackhole"}}
	outboundIDs := map[string]bool{"direct": true, "block": true}
	for _, out := range s.Outbounds {
		if out.NodeID != nodeID {
			continue
		}
		if out.Protocol != "socks" && out.Protocol != "http" {
			return model.Desired{}, fmt.Errorf("unsupported outbound %s", out.Protocol)
		}
		host, port, user, pass := out.Host, out.Port, out.Username, out.Password
		if out.LandingInboundID != "" {
			landing, ok := inboundByID[out.LandingInboundID]
			if !ok || !landing.Enabled || (landing.Protocol != "socks" && landing.Protocol != "http") {
				return model.Desired{}, errors.New("invalid landing inbound")
			}
			var landingNode *model.Node
			for i := range s.Nodes {
				if s.Nodes[i].ID == landing.NodeID {
					landingNode = &s.Nodes[i]
					break
				}
			}
			if landingNode == nil || landingNode.PrivateIP == "" {
				return model.Desired{}, errors.New("landing node missing private IP")
			}
			if landing.NodeID == nodeID {
				return model.Desired{}, errors.New("managed landing must be on another node")
			}
			host, port, user, pass = landingNode.PrivateIP, landing.Port, landing.ServiceUser, landing.ServicePassword
			if out.Protocol != landing.Protocol {
				return model.Desired{}, errors.New("outbound/landing protocol mismatch")
			}
		}
		if host == "" || port < 1 || port > 65535 {
			return model.Desired{}, errors.New("invalid upstream address")
		}
		server := map[string]any{"address": host, "port": port}
		if user != "" {
			server["users"] = []any{map[string]string{"user": user, "pass": pass}}
		}
		outbounds = append(outbounds, map[string]any{"tag": "out-" + out.ID, "protocol": out.Protocol, "settings": map[string]any{"servers": []any{server}}})
		outboundIDs[out.ID] = true
	}
	rules := append([]model.Rule(nil), s.Rules...)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Position < rules[j].Position })
	var routing []any
	for _, rule := range rules {
		if rule.NodeID != nodeID {
			continue
		}
		if !outboundIDs[rule.OutboundID] {
			return model.Desired{}, fmt.Errorf("rule %s references missing outbound", rule.ID)
		}
		base := map[string]any{"type": "field"}
		if rule.OutboundID == "direct" || rule.OutboundID == "block" {
			base["outboundTag"] = rule.OutboundID
		} else {
			base["outboundTag"] = "out-" + rule.OutboundID
		}
		if rule.InboundID != "" {
			base["inboundTag"] = []string{"in-" + rule.InboundID}
		}
		if rule.PersonID != "" {
			var emails []string
			for _, a := range s.Assignments {
				if a.PersonID == rule.PersonID {
					p := people[a.PersonID]
					if p.Disabled || (p.QuotaBytes > 0 && p.UsedBytes >= p.QuotaBytes) || (p.ExpiresAt != nil && p.ExpiresAt.Before(now())) {
						continue
					}
					if in, ok := inboundByID[a.InboundID]; ok && in.NodeID == nodeID {
						emails = append(emails, UserEmail(a))
					}
				}
			}
			if len(emails) == 0 {
				continue
			}
			base["user"] = emails
		}
		if len(rule.Domains) > 0 {
			c := clone(base)
			c["domain"] = rule.Domains
			routing = append(routing, c)
		}
		if len(rule.CIDRs) > 0 {
			c := clone(base)
			c["ip"] = rule.CIDRs
			routing = append(routing, c)
		}
		if len(rule.Domains) == 0 && len(rule.CIDRs) == 0 {
			routing = append(routing, base)
		}
	}
	config := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"api":      map[string]any{"tag": "api", "listen": "127.0.0.1:10085", "services": []string{"StatsService"}},
		"stats":    map[string]any{},
		"policy":   map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}}, "system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true}},
		"inbounds": inbounds, "outbounds": outbounds,
		"routing": map[string]any{"domainStrategy": "IPIfNonMatch", "rules": routing},
	}
	b, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return model.Desired{}, err
	}
	return model.Desired{Revision: s.Revision, Config: b, TLSNames: unique(tlsNames)}, nil
}

var now = func() time.Time { return time.Now() }

func clone(m map[string]any) map[string]any {
	n := map[string]any{}
	for k, v := range m {
		n[k] = v
	}
	return n
}
func unique(a []string) []string {
	m := map[string]bool{}
	var b []string
	for _, v := range a {
		if !m[v] {
			m[v] = true
			b = append(b, v)
		}
	}
	return b
}
func validDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, "/\\ :") {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return strings.Contains(s, ".")
}
