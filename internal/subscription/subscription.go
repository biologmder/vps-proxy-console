package subscription

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/biologmder/vps-proxy-console/internal/model"
	"gopkg.in/yaml.v3"
)

type Entry struct {
	Link  string
	Proxy map[string]any
}

func Entries(st model.State, p model.Person) []Entry {
	if p.Disabled || (p.ExpiresAt != nil && p.ExpiresAt.Before(time.Now())) || (p.QuotaBytes > 0 && p.UsedBytes >= p.QuotaBytes) {
		return nil
	}
	nodes := map[string]model.Node{}
	for _, n := range st.Nodes {
		nodes[n.ID] = n
	}
	inbounds := map[string]model.Inbound{}
	for _, in := range st.Inbounds {
		inbounds[in.ID] = in
	}
	var result []Entry
	for _, a := range st.Assignments {
		if a.PersonID != p.ID {
			continue
		}
		in, ok := inbounds[a.InboundID]
		if !ok || !in.Enabled || in.Protocol == "socks" || in.Protocol == "http" {
			continue
		}
		n, ok := nodes[in.NodeID]
		if !ok {
			continue
		}
		name := p.Name + " - " + n.Name + " - " + in.Name
		server := n.Domain
		port := strconv.Itoa(in.Port)
		q := url.Values{}
		var link string
		var proxy map[string]any
		switch in.Protocol {
		case "vless-tls", "vless-reality":
			q.Set("encryption", "none")
			q.Set("type", "tcp")
			q.Set("sni", in.Domain)
			proxy = map[string]any{"name": name, "type": "vless", "server": server, "port": in.Port, "uuid": a.Credential, "tls": true, "servername": in.Domain, "udp": true}
			if in.Protocol == "vless-reality" {
				q.Set("security", "reality")
				q.Set("pbk", in.RealityPublicKey)
				q.Set("sid", in.RealityShortID)
				q.Set("fp", "chrome")
				q.Set("flow", "xtls-rprx-vision")
				proxy["reality-opts"] = map[string]any{"public-key": in.RealityPublicKey, "short-id": in.RealityShortID}
				proxy["client-fingerprint"] = "chrome"
				proxy["flow"] = "xtls-rprx-vision"
			} else {
				q.Set("security", "tls")
			}
			link = "vless://" + a.Credential + "@" + server + ":" + port + "?" + q.Encode() + "#" + url.QueryEscape(name)
		case "trojan-tls":
			q.Set("security", "tls")
			q.Set("sni", in.Domain)
			q.Set("type", "tcp")
			link = "trojan://" + url.QueryEscape(a.Credential) + "@" + server + ":" + port + "?" + q.Encode() + "#" + url.QueryEscape(name)
			proxy = map[string]any{"name": name, "type": "trojan", "server": server, "port": in.Port, "password": a.Credential, "sni": in.Domain, "udp": true}
		case "ss":
			method := "aes-256-gcm"
			userinfo := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + a.Credential))
			link = "ss://" + userinfo + "@" + server + ":" + port + "#" + url.QueryEscape(name)
			proxy = map[string]any{"name": name, "type": "ss", "server": server, "port": in.Port, "cipher": method, "password": a.Credential, "udp": true}
		case "vmess-ws-tls":
			path := in.Path
			if path == "" {
				path = "/ws"
			}
			vm := map[string]any{"v": "2", "ps": name, "add": server, "port": port, "id": a.Credential, "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": in.Domain, "path": path, "tls": "tls", "sni": in.Domain}
			b, _ := json.Marshal(vm)
			link = "vmess://" + base64.StdEncoding.EncodeToString(b)
			proxy = map[string]any{"name": name, "type": "vmess", "server": server, "port": in.Port, "uuid": a.Credential, "alterId": 0, "cipher": "auto", "tls": true, "servername": in.Domain, "network": "ws", "ws-opts": map[string]any{"path": path, "headers": map[string]string{"Host": in.Domain}}, "udp": true}
		default:
			continue
		}
		result = append(result, Entry{link, proxy})
	}
	return result
}

func Raw(entries []Entry) []byte {
	var links []string
	for _, e := range entries {
		links = append(links, e.Link)
	}
	return []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
}

func Mihomo(entries []Entry) ([]byte, error) {
	var proxies []map[string]any
	names := []string{}
	for _, e := range entries {
		proxies = append(proxies, e.Proxy)
		names = append(names, e.Proxy["name"].(string))
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no active proxies")
	}
	config := map[string]any{"mixed-port": 7890, "allow-lan": false, "mode": "rule", "log-level": "warning", "proxies": proxies, "proxy-groups": []any{map[string]any{"name": "自动选择", "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 300, "proxies": names}, map[string]any{"name": "节点选择", "type": "select", "proxies": append([]string{"自动选择"}, names...)}}, "rules": []string{"MATCH,节点选择"}}
	return yaml.Marshal(config)
}
