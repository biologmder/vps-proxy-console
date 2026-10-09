package xray

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
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
		in.Normalize()
		inboundByID[in.ID] = in
	}
	var inbounds []any
	var tlsNames []string
	portSeen := map[int]bool{80: true, 10085: true}
	for _, in := range s.Inbounds {
		in.Normalize()
		if in.NodeID != nodeID || !in.Enabled {
			continue
		}
		if in.Port < 1 || in.Port > 65535 || portSeen[in.Port] {
			return model.Desired{}, fmt.Errorf("invalid/duplicate port %d", in.Port)
		}
		portSeen[in.Port] = true
		if err := in.CheckCombination(); err != nil {
			return model.Desired{}, fmt.Errorf("inbound %s: %w", in.Name, err)
		}
		cfg := map[string]any{"tag": "in-" + in.ID, "port": in.Port, "listen": in.Listen}
		if cfg["listen"] == "" {
			cfg["listen"] = "0.0.0.0"
		}
		ss2022 := model.SS2022KeyLen(in.SSMethod)
		clients := []any{}
		for _, a := range assigned[in.ID] {
			if !active(people[a.PersonID]) {
				continue
			}
			client := map[string]any{"email": UserEmail(a)}
			switch in.Protocol {
			case model.ProtoVLESS:
				client["id"] = a.Credential
				if in.Flow != "" {
					client["flow"] = in.Flow
				}
			case model.ProtoVMess:
				client["id"] = a.Credential
			case model.ProtoTrojan:
				client["password"] = a.Credential
			case model.ProtoShadowsocks:
				if ss2022 > 0 && !validKey(a.Credential, ss2022) {
					return model.Desired{}, fmt.Errorf("assignment %s has no valid %s key; delete and recreate it", a.ID, in.SSMethod)
				}
				client["password"] = a.Credential
				if ss2022 == 0 {
					client["method"] = in.SSMethod
				}
			}
			clients = append(clients, client)
		}
		switch in.Protocol {
		case model.ProtoVLESS:
			cfg["protocol"] = "vless"
			cfg["settings"] = map[string]any{"clients": clients, "decryption": "none"}
		case model.ProtoVMess:
			cfg["protocol"] = "vmess"
			cfg["settings"] = map[string]any{"clients": clients}
		case model.ProtoTrojan:
			cfg["protocol"] = "trojan"
			cfg["settings"] = map[string]any{"clients": clients}
		case model.ProtoShadowsocks:
			if in.SSServerKey == "" || (ss2022 > 0 && !validKey(in.SSServerKey, ss2022)) {
				return model.Desired{}, fmt.Errorf("shadowsocks inbound %s has a missing or invalid server key", in.Name)
			}
			cfg["protocol"] = "shadowsocks"
			cfg["settings"] = map[string]any{"network": "tcp,udp", "method": in.SSMethod, "password": in.SSServerKey, "users": clients}
		case model.ProtoSOCKS, model.ProtoHTTP:
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
		}
		if in.Protocol != model.ProtoShadowsocks && !in.IsLanding() {
			stream, err := streamSettings(in)
			if err != nil {
				return model.Desired{}, fmt.Errorf("inbound %s: %w", in.Name, err)
			}
			if in.Security == "tls" {
				tlsNames = append(tlsNames, in.Domain)
			}
			cfg["streamSettings"] = stream
		}
		if !in.IsLanding() {
			cfg["sniffing"] = map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}
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
			if !ok || !landing.Enabled || !landing.IsLanding() {
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
	// Proxy users must never reach the node itself or private networks: that would
	// expose the Xray stats API on 127.0.0.1 and any tunnel peers. IPOnDemand resolves
	// domains when this rule is evaluated, so names pointing at private addresses
	// are blocked as well. Xray's own connections to landing nodes are not routed.
	routing := []any{map[string]any{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "block"}}
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
					if !active(people[a.PersonID]) {
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
		"routing": map[string]any{"domainStrategy": "IPOnDemand", "rules": routing},
	}
	b, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return model.Desired{}, err
	}
	return model.Desired{Revision: s.Revision, Config: b, TLSNames: unique(tlsNames)}, nil
}

func streamSettings(in model.Inbound) (map[string]any, error) {
	stream := map[string]any{"network": in.Network}
	switch in.Network {
	case "ws":
		stream["wsSettings"] = map[string]any{"path": in.Path, "host": in.Host}
	case "httpupgrade":
		stream["httpupgradeSettings"] = map[string]any{"path": in.Path, "host": in.Host}
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": in.ServiceName}
	case "xhttp":
		stream["xhttpSettings"] = map[string]any{"path": in.Path, "host": in.Host, "mode": in.XHTTPMode}
	}
	switch in.Security {
	case "tls":
		if !validDomain(in.Domain) {
			return nil, fmt.Errorf("invalid certificate domain %q", in.Domain)
		}
		tls := map[string]any{"certificates": []any{map[string]string{"certificateFile": "/data/certs/" + in.Domain + ".crt", "keyFile": "/data/certs/" + in.Domain + ".key"}}}
		switch in.Network {
		case "ws", "httpupgrade":
			tls["alpn"] = []string{"http/1.1"}
		case "grpc":
			tls["alpn"] = []string{"h2"}
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = tls
	case "reality":
		if !validDomain(in.Domain) {
			return nil, fmt.Errorf("invalid REALITY server name %q", in.Domain)
		}
		if in.RealityDest == "" || in.RealityPrivateKey == "" || in.RealityShortID == "" {
			return nil, errors.New("REALITY destination/key/short ID required")
		}
		host, rawPort, err := net.SplitHostPort(in.RealityDest)
		port, portErr := strconv.Atoi(rawPort)
		if err != nil || portErr != nil || host == "" || port < 1 || port > 65535 {
			return nil, errors.New("REALITY target must be host:port")
		}
		if len(in.RealityShortID) > 16 || len(in.RealityShortID)%2 != 0 {
			return nil, errors.New("REALITY short ID must contain an even number of hex digits, at most 16")
		}
		if _, err := hex.DecodeString(in.RealityShortID); err != nil {
			return nil, errors.New("REALITY short ID must be hexadecimal")
		}
		stream["security"] = "reality"
		stream["realitySettings"] = map[string]any{"show": false, "dest": in.RealityDest, "xver": 0, "serverNames": []string{in.Domain}, "privateKey": in.RealityPrivateKey, "shortIds": []string{in.RealityShortID}}
	default:
		stream["security"] = "none"
	}
	return stream, nil
}

var now = func() time.Time { return time.Now() }

func active(p model.Person) bool {
	if p.ID == "" || p.Disabled || (p.QuotaBytes > 0 && p.UsedBytes >= p.QuotaBytes) {
		return false
	}
	return p.ExpiresAt == nil || p.ExpiresAt.IsZero() || !p.ExpiresAt.Before(now())
}

func validKey(s string, n int) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == n
}

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
