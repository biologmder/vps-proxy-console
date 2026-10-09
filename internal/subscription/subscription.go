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

// Entry is one distributable proxy. Proxy is nil when Mihomo cannot express the
// combination; the share link is still included in the Base64 subscription.
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
		in.Normalize()
		inbounds[in.ID] = in
	}
	var result []Entry
	for _, a := range st.Assignments {
		if a.PersonID != p.ID {
			continue
		}
		in, ok := inbounds[a.InboundID]
		if !ok || !in.Enabled || in.IsLanding() {
			continue
		}
		n, ok := nodes[in.NodeID]
		if !ok {
			continue
		}
		if e, ok := entry(p.Name+" - "+n.Name+" - "+in.Name, n.Domain, in, a.Credential); ok {
			result = append(result, e)
		}
	}
	return result
}

func entry(name, server string, in model.Inbound, credential string) (Entry, bool) {
	port := strconv.Itoa(in.Port)
	addr := server + ":" + port
	fragment := "#" + url.QueryEscape(name)
	base := map[string]any{"name": name, "server": server, "port": in.Port, "udp": true}
	switch in.Protocol {
	case model.ProtoVLESS:
		q := transportQuery(in)
		q.Set("encryption", "none")
		if in.Flow != "" {
			q.Set("flow", in.Flow)
		}
		proxy := mihomoTransport(in, base)
		if proxy != nil {
			proxy["type"] = "vless"
			proxy["uuid"] = credential
			if in.Flow != "" {
				proxy["flow"] = in.Flow
			}
		}
		return Entry{"vless://" + credential + "@" + addr + "?" + q.Encode() + fragment, proxy}, true
	case model.ProtoTrojan:
		q := transportQuery(in)
		proxy := mihomoTransport(in, base)
		if proxy != nil {
			proxy["type"] = "trojan"
			proxy["password"] = credential
			if in.Security == "tls" {
				delete(proxy, "tls")
				delete(proxy, "servername")
				proxy["sni"] = in.Domain
			}
		}
		return Entry{"trojan://" + url.QueryEscape(credential) + "@" + addr + "?" + q.Encode() + fragment, proxy}, true
	case model.ProtoVMess:
		vm := map[string]any{"v": "2", "ps": name, "add": server, "port": port, "id": credential, "aid": "0", "scy": "auto", "net": in.Network, "type": "none", "host": in.Host, "path": in.Path, "tls": ""}
		if in.Network == "grpc" {
			vm["type"], vm["path"] = "gun", in.ServiceName
		}
		if in.Security == "tls" {
			vm["tls"], vm["sni"] = "tls", in.Domain
			if in.Host == "" && in.Network != "tcp" && in.Network != "grpc" {
				vm["host"] = in.Domain
			}
		}
		b, _ := json.Marshal(vm)
		proxy := mihomoTransport(in, base)
		if proxy != nil {
			proxy["type"] = "vmess"
			proxy["uuid"] = credential
			proxy["alterId"] = 0
			proxy["cipher"] = "auto"
		}
		return Entry{"vmess://" + base64.StdEncoding.EncodeToString(b), proxy}, true
	case model.ProtoShadowsocks:
		proxy := clone(base)
		proxy["type"] = "ss"
		proxy["cipher"] = in.SSMethod
		var link string
		if model.SS2022KeyLen(in.SSMethod) > 0 {
			// SIP022: multi-user password is "serverKey:userKey", userinfo is percent-encoded, not Base64.
			proxy["password"] = in.SSServerKey + ":" + credential
			link = "ss://" + url.QueryEscape(in.SSMethod) + ":" + url.QueryEscape(in.SSServerKey) + ":" + url.QueryEscape(credential) + "@" + addr + fragment
		} else {
			proxy["password"] = credential
			link = "ss://" + base64.RawURLEncoding.EncodeToString([]byte(in.SSMethod+":"+credential)) + "@" + addr + fragment
		}
		return Entry{link, proxy}, true
	}
	return Entry{}, false
}

// transportQuery builds the shared-link query parameters used by vless:// and trojan://.
func transportQuery(in model.Inbound) url.Values {
	q := url.Values{}
	q.Set("type", in.Network)
	q.Set("security", in.Security)
	switch in.Network {
	case "ws", "httpupgrade", "xhttp":
		q.Set("path", in.Path)
		if host := hostHeader(in); host != "" {
			q.Set("host", host)
		}
		if in.Network == "xhttp" {
			q.Set("mode", in.XHTTPMode)
		}
	case "grpc":
		q.Set("serviceName", in.ServiceName)
		q.Set("mode", "gun")
	}
	switch in.Security {
	case "tls":
		q.Set("sni", in.Domain)
		q.Set("fp", "chrome")
	case "reality":
		q.Set("sni", in.Domain)
		q.Set("fp", in.Fingerprint)
		q.Set("pbk", in.RealityPublicKey)
		q.Set("sid", in.RealityShortID)
	}
	return q
}

func hostHeader(in model.Inbound) string {
	if in.Host != "" {
		return in.Host
	}
	if in.Security == "tls" {
		return in.Domain
	}
	return ""
}

// mihomoTransport fills the transport and TLS fields of a Mihomo proxy. It returns nil
// for combinations Mihomo cannot represent (XHTTP).
func mihomoTransport(in model.Inbound, base map[string]any) map[string]any {
	proxy := clone(base)
	switch in.Network {
	case "tcp":
	case "ws", "httpupgrade":
		proxy["network"] = "ws"
		opts := map[string]any{"path": in.Path}
		if host := hostHeader(in); host != "" {
			opts["headers"] = map[string]string{"Host": host}
		}
		if in.Network == "httpupgrade" {
			opts["v2ray-http-upgrade"] = true
		}
		proxy["ws-opts"] = opts
	case "grpc":
		proxy["network"] = "grpc"
		proxy["grpc-opts"] = map[string]any{"grpc-service-name": in.ServiceName}
	default:
		return nil
	}
	switch in.Security {
	case "tls":
		proxy["tls"] = true
		proxy["servername"] = in.Domain
		proxy["client-fingerprint"] = "chrome"
	case "reality":
		if in.Protocol != model.ProtoVLESS {
			return nil
		}
		proxy["tls"] = true
		proxy["servername"] = in.Domain
		proxy["client-fingerprint"] = in.Fingerprint
		proxy["reality-opts"] = map[string]any{"public-key": in.RealityPublicKey, "short-id": in.RealityShortID}
	}
	return proxy
}

func clone(m map[string]any) map[string]any {
	n := make(map[string]any, len(m))
	for k, v := range m {
		n[k] = v
	}
	return n
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
		if e.Proxy == nil {
			continue
		}
		proxies = append(proxies, e.Proxy)
		names = append(names, e.Proxy["name"].(string))
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no active proxies")
	}
	config := map[string]any{"mixed-port": 7890, "allow-lan": false, "mode": "rule", "log-level": "warning", "proxies": proxies, "proxy-groups": []any{map[string]any{"name": "自动选择", "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 300, "proxies": names}, map[string]any{"name": "节点选择", "type": "select", "proxies": append([]string{"自动选择"}, names...)}}, "rules": []string{"MATCH,节点选择"}}
	return yaml.Marshal(config)
}
