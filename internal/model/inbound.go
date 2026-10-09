package model

import (
	"errors"
	"fmt"
	"strings"
)

// Inbound protocols. Older records stored a fixed protocol+transport+security
// combination in Protocol (for example "vless-reality"); Normalize maps those
// onto the separate Protocol/Network/Security fields.
const (
	ProtoVLESS       = "vless"
	ProtoVMess       = "vmess"
	ProtoTrojan      = "trojan"
	ProtoShadowsocks = "shadowsocks"
	ProtoSOCKS       = "socks"
	ProtoHTTP        = "http"

	FlowVision = "xtls-rprx-vision"
)

// SSMethods lists the Shadowsocks ciphers the panel can compile and distribute.
var SSMethods = []string{
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
	"aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305",
}

// SS2022KeyLen returns the key length in bytes for a Shadowsocks 2022 method, or 0.
func SS2022KeyLen(method string) int {
	switch method {
	case "2022-blake3-aes-128-gcm":
		return 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32
	}
	return 0
}

// Normalize converts legacy combined protocol names and fills defaults. It is idempotent.
func (in *Inbound) Normalize() {
	switch in.Protocol {
	case "vless-tls":
		in.Protocol, in.Network, in.Security = ProtoVLESS, "tcp", "tls"
	case "vless-reality":
		in.Protocol, in.Network, in.Security = ProtoVLESS, "tcp", "reality"
		if in.Flow == "" {
			in.Flow = FlowVision
		}
	case "trojan-tls":
		in.Protocol, in.Network, in.Security = ProtoTrojan, "tcp", "tls"
	case "vmess-ws-tls":
		in.Protocol, in.Network, in.Security = ProtoVMess, "ws", "tls"
	case "ss":
		in.Protocol = ProtoShadowsocks
	}
	switch in.Protocol {
	case ProtoShadowsocks:
		in.Network, in.Security = "tcp", "none"
		if in.SSMethod == "" {
			in.SSMethod = "aes-256-gcm"
		}
	case ProtoSOCKS, ProtoHTTP:
		in.Network, in.Security = "tcp", "none"
	}
	if in.Network == "" {
		in.Network = "tcp"
	}
	if in.Security == "" {
		in.Security = "none"
	}
	if (in.Network == "ws" || in.Network == "httpupgrade") && in.Path == "" {
		in.Path = "/ws"
	}
	if in.Network == "xhttp" && in.Path == "" {
		in.Path = "/xhttp"
	}
	if in.Network == "grpc" && in.ServiceName == "" {
		in.ServiceName = "grpc"
	}
	if in.Network == "xhttp" && in.XHTTPMode == "" {
		in.XHTTPMode = "auto"
	}
	if in.Security == "reality" && in.Fingerprint == "" {
		in.Fingerprint = "chrome"
	}
}

// IsLanding reports whether the inbound is a private relay endpoint that never appears in subscriptions.
func (in Inbound) IsLanding() bool {
	return in.Protocol == ProtoSOCKS || in.Protocol == ProtoHTTP
}

// UsesUUID reports whether client credentials for the inbound are UUIDs.
func (in Inbound) UsesUUID() bool {
	return in.Protocol == ProtoVLESS || in.Protocol == ProtoVMess
}

// CheckCombination validates protocol/transport/security against what the
// compiler and subscription generator support. The inbound must be normalized.
func (in Inbound) CheckCombination() error {
	var networks, securities map[string]bool
	switch in.Protocol {
	case ProtoVLESS:
		networks = set("tcp", "ws", "grpc", "httpupgrade", "xhttp")
		securities = set("none", "tls", "reality")
	case ProtoVMess:
		networks = set("tcp", "ws", "grpc", "httpupgrade")
		securities = set("none", "tls")
	case ProtoTrojan:
		networks = set("tcp", "ws", "grpc", "httpupgrade")
		securities = set("tls", "reality")
	case ProtoShadowsocks:
		networks, securities = set("tcp"), set("none")
		if !contains(SSMethods, in.SSMethod) {
			return fmt.Errorf("unsupported Shadowsocks method %q", in.SSMethod)
		}
	case ProtoSOCKS, ProtoHTTP:
		networks, securities = set("tcp"), set("none")
	default:
		return fmt.Errorf("unsupported protocol %s", in.Protocol)
	}
	if !networks[in.Network] {
		return fmt.Errorf("%s does not support transport %s", in.Protocol, in.Network)
	}
	if !securities[in.Security] {
		return fmt.Errorf("%s does not support security %s", in.Protocol, in.Security)
	}
	if in.Security == "reality" && in.Network != "tcp" && in.Network != "grpc" && in.Network != "xhttp" {
		return errors.New("REALITY requires TCP, gRPC or XHTTP transport")
	}
	if in.Flow != "" && (in.Flow != FlowVision || in.Protocol != ProtoVLESS || in.Network != "tcp" || in.Security == "none") {
		return errors.New("xtls-rprx-vision flow requires VLESS over TCP with TLS or REALITY")
	}
	if strings.ContainsAny(in.Path+in.Host+in.ServiceName, " \r\n\"") {
		return errors.New("transport path/host/service name contains invalid characters")
	}
	if (in.Network == "ws" || in.Network == "httpupgrade" || in.Network == "xhttp") && !strings.HasPrefix(in.Path, "/") {
		return errors.New("transport path must start with /")
	}
	return nil
}

func set(v ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range v {
		m[x] = true
	}
	return m
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
