package model

import "time"

type Node struct {
	ID              string               `json:"id"`
	Name            string               `json:"name"`
	Domain          string               `json:"domain"`
	PrivateIP       string               `json:"private_ip"`
	TokenHash       string               `json:"-"`
	LastSeen        time.Time            `json:"last_seen"`
	AppliedRevision int64                `json:"applied_revision"`
	ApplyError      string               `json:"apply_error"`
	CertExpiry      map[string]time.Time `json:"cert_expiry,omitempty"`
}

type Person struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	QuotaBytes int64      `json:"quota_bytes"`
	UsedBytes  int64      `json:"used_bytes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	TokenHash  string     `json:"-"`
	Disabled   bool       `json:"disabled"`
	Notified80 bool       `json:"-"`
}

type Inbound struct {
	ID                string `json:"id"`
	NodeID            string `json:"node_id"`
	Name              string `json:"name"`
	Protocol          string `json:"protocol"`
	Listen            string `json:"listen"`
	Port              int    `json:"port"`
	Domain            string `json:"domain"`
	Path              string `json:"path,omitempty"`
	RealityDest       string `json:"reality_dest,omitempty"`
	RealityPrivateKey string `json:"reality_private_key,omitempty"`
	RealityPublicKey  string `json:"reality_public_key,omitempty"`
	RealityShortID    string `json:"reality_short_id,omitempty"`
	ServiceUser       string `json:"service_user,omitempty"`
	ServicePassword   string `json:"service_password,omitempty"`
	SSServerKey       string `json:"ss_server_key,omitempty"`
	Enabled           bool   `json:"enabled"`
}

type Outbound struct {
	ID               string `json:"id"`
	NodeID           string `json:"node_id"`
	Name             string `json:"name"`
	Protocol         string `json:"protocol"`
	Host             string `json:"host,omitempty"`
	Port             int    `json:"port,omitempty"`
	Username         string `json:"username,omitempty"`
	Password         string `json:"password,omitempty"`
	LandingInboundID string `json:"landing_inbound_id,omitempty"`
}

type Rule struct {
	ID         string   `json:"id"`
	NodeID     string   `json:"node_id"`
	Position   int      `json:"position"`
	PersonID   string   `json:"person_id,omitempty"`
	InboundID  string   `json:"inbound_id,omitempty"`
	Domains    []string `json:"domains,omitempty"`
	CIDRs      []string `json:"cidrs,omitempty"`
	OutboundID string   `json:"outbound_id"`
}

type Assignment struct {
	ID         string `json:"id"`
	PersonID   string `json:"person_id"`
	InboundID  string `json:"inbound_id"`
	Credential string `json:"credential"`
}

type State struct {
	Revision    int64        `json:"revision"`
	Nodes       []Node       `json:"nodes"`
	People      []Person     `json:"people"`
	Inbounds    []Inbound    `json:"inbounds"`
	Outbounds   []Outbound   `json:"outbounds"`
	Rules       []Rule       `json:"rules"`
	Assignments []Assignment `json:"assignments"`
}

type Desired struct {
	Revision int64    `json:"revision"`
	Config   []byte   `json:"config"`
	TLSNames []string `json:"tls_names"`
}

type Report struct {
	Revision   int64                `json:"revision"`
	ApplyError string               `json:"apply_error"`
	Totals     map[string]int64     `json:"totals"`
	CertExpiry map[string]time.Time `json:"cert_expiry,omitempty"`
}
