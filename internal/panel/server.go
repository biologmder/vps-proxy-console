package panel

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/biologmder/vps-proxy-console/internal/model"
	"github.com/biologmder/vps-proxy-console/internal/store"
	"github.com/biologmder/vps-proxy-console/internal/subscription"
	"github.com/biologmder/vps-proxy-console/internal/xray"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	Store         *store.Store
	PasswordHash  []byte
	PublicURL     string
	WebDir        string
	TelegramToken string
	TelegramChat  string
	mu            sync.Mutex
	sessions      map[string]time.Time
	loginAttempts map[string][]time.Time
}

func New(st *store.Store, password, publicURL, webDir string) (*Server, error) {
	if len(password) < 12 {
		return nil, errors.New("ADMIN_PASSWORD must contain at least 12 characters")
	}
	publicURL = strings.TrimRight(publicURL, "/")
	parsedURL, err := url.Parse(publicURL)
	if err != nil || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.Path != "" || parsedURL.RawQuery != "" || parsedURL.Fragment != "" || strings.ContainsAny(publicURL, "\r\n") {
		return nil, errors.New("PUBLIC_URL must be an absolute panel origin without a path")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &Server{Store: st, PasswordHash: h, PublicURL: publicURL, WebDir: webDir, sessions: map[string]time.Time{}, loginAttempts: map[string][]time.Time{}}, nil
}

func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /api/v1/login", s.login)
	m.HandleFunc("POST /api/v1/logout", s.admin(s.logout))
	m.HandleFunc("GET /api/v1/state", s.admin(s.state))
	m.HandleFunc("POST /api/v1/{kind}", s.admin(s.create))
	m.HandleFunc("PUT /api/v1/{kind}/{id}", s.admin(s.update))
	m.HandleFunc("DELETE /api/v1/{kind}/{id}", s.admin(s.delete))
	m.HandleFunc("POST /api/v1/{kind}/{id}/rotate", s.admin(s.rotate))
	m.HandleFunc("GET /agent/v1/sync", s.agent(s.sync))
	m.HandleFunc("POST /agent/v1/report", s.agent(s.report))
	m.HandleFunc("GET /sub/{token}", s.subscription)
	if s.WebDir != "" {
		m.Handle("/", http.FileServer(http.Dir(s.WebDir)))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		m.ServeHTTP(w, r)
	})
}

func fail(w http.ResponseWriter, status int, msg string) { http.Error(w, msg, status) }
func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func decode(r *http.Request, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}
func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func id() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func uuid() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	s.mu.Lock()
	var recent []time.Time
	for _, t := range s.loginAttempts[ip] {
		if time.Since(t) < 10*time.Minute {
			recent = append(recent, t)
		}
	}
	s.loginAttempts[ip] = recent
	limited := len(recent) >= 8
	s.mu.Unlock()
	if limited {
		fail(w, 429, "too many login attempts")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "invalid request")
		return
	}
	if bcrypt.CompareHashAndPassword(s.PasswordHash, []byte(in.Password)) != nil {
		s.mu.Lock()
		s.loginAttempts[ip] = append(s.loginAttempts[ip], time.Now())
		s.mu.Unlock()
		fail(w, 401, "invalid password")
		return
	}
	token := random(32)
	s.mu.Lock()
	s.sessions[token] = time.Now().Add(24 * time.Hour)
	delete(s.loginAttempts, ip)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "vpc_session", Value: token, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(s.PublicURL, "https://"), SameSite: http.SameSiteStrictMode, MaxAge: 86400})
	jsonOut(w, 200, map[string]bool{"ok": true})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("vpc_session"); e == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "vpc_session", Path: "/", MaxAge: -1, HttpOnly: true})
	jsonOut(w, 200, map[string]bool{"ok": true})
}
func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("vpc_session")
		if err != nil {
			fail(w, 401, "login required")
			return
		}
		s.mu.Lock()
		until, ok := s.sessions[c.Value]
		if ok && time.Now().After(until) {
			delete(s.sessions, c.Value)
			ok = false
		}
		s.mu.Unlock()
		if !ok {
			fail(w, 401, "login required")
			return
		}
		if r.Method != "GET" {
			origin := r.Header.Get("Origin")
			if origin != "" {
				u, e := url.Parse(origin)
				if e != nil || u.Host != r.Host {
					fail(w, 403, "invalid origin")
					return
				}
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") && r.Method != "DELETE" {
				fail(w, 415, "JSON required")
				return
			}
		}
		next(w, r)
	}
}
func (s *Server) agent(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nodeID := r.Header.Get("X-Node-ID")
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || !s.Store.CheckSecret("nodes", nodeID, strings.TrimPrefix(auth, "Bearer ")) {
			fail(w, 401, "invalid node token")
			return
		}
		next(w, r, nodeID)
	}
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.State()
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	jsonOut(w, 200, v)
}
func allowedKind(k string) bool {
	switch k {
	case "nodes", "people", "inbounds", "outbounds", "rules", "assignments":
		return true
	}
	return false
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if !allowedKind(kind) {
		fail(w, 404, "unknown resource")
		return
	}
	newID := id()
	var v any
	var secret string
	switch kind {
	case "nodes":
		var x model.Node
		if err := decode(r, &x); err != nil {
			fail(w, 400, err.Error())
			return
		}
		x.ID = newID
		x.LastSeen = time.Time{}
		x.AppliedRevision = 0
		x.ApplyError = ""
		v = x
		secret = random(32)
	case "people":
		var x model.Person
		if err := decode(r, &x); err != nil {
			fail(w, 400, err.Error())
			return
		}
		x.ID = newID
		x.UsedBytes = 0
		v = x
		secret = random(32)
	case "inbounds":
		var x model.Inbound
		if err := decode(r, &x); err != nil {
			fail(w, 400, err.Error())
			return
		}
		x.ID = newID
		if x.Protocol == "ss" && x.SSServerKey == "" {
			x.SSServerKey = random(24)
		}
		if x.Protocol == "socks" || x.Protocol == "http" {
			if x.ServiceUser == "" {
				x.ServiceUser = "relay"
			}
			if x.ServicePassword == "" {
				x.ServicePassword = random(24)
			}
		}
		if x.Protocol == "vless-reality" && x.RealityPrivateKey == "" {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				fail(w, 500, err.Error())
				return
			}
			x.RealityPrivateKey = base64.RawURLEncoding.EncodeToString(key.Bytes())
			x.RealityPublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
			x.RealityShortID = randomHex(4)
		}
		v = x
	case "outbounds":
		var x model.Outbound
		if err := decode(r, &x); err != nil {
			fail(w, 400, err.Error())
			return
		}
		x.ID = newID
		v = x
	case "rules":
		var x model.Rule
		if err := decode(r, &x); err != nil {
			fail(w, 400, err.Error())
			return
		}
		x.ID = newID
		v = x
	case "assignments":
		var x model.Assignment
		if err := decode(r, &x); err != nil {
			fail(w, 400, err.Error())
			return
		}
		x.ID = newID
		st, _ := s.Store.State()
		var protocol string
		for _, in := range st.Inbounds {
			if in.ID == x.InboundID {
				protocol = in.Protocol
				break
			}
		}
		if protocol == "vless-tls" || protocol == "vless-reality" || protocol == "vmess-ws-tls" {
			x.Credential = uuid()
		} else {
			x.Credential = random(24)
		}
		v = x
	}
	if err := s.validate(kind, newID, v, false); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err := s.Store.Upsert(kind, newID, v, true); err != nil {
		fail(w, 500, err.Error())
		return
	}
	if secret != "" {
		if err := s.Store.SetSecret(kind, newID, secret); err != nil {
			fail(w, 500, err.Error())
			return
		}
	}
	subscriptionURL := ""
	deployCommand := ""
	if kind == "people" {
		subscriptionURL = s.subURL(secret)
	} else if kind == "nodes" {
		deployCommand = s.agentDeployCommand(newID, secret)
	}
	jsonOut(w, 201, map[string]any{"item": v, "token": secret, "subscription_url": subscriptionURL, "deploy_command": deployCommand})
}

func (s *Server) update(w http.ResponseWriter, r *http.Request) {
	kind, id := r.PathValue("kind"), r.PathValue("id")
	if !allowedKind(kind) {
		fail(w, 404, "unknown resource")
		return
	}
	st, err := s.Store.State()
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	if !exists(st, kind, id) {
		fail(w, 404, "not found")
		return
	}
	var v any
	switch kind {
	case "nodes":
		var x model.Node
		if err = decode(r, &x); err == nil {
			x.ID = id
			for _, old := range st.Nodes {
				if old.ID == id {
					x.LastSeen = old.LastSeen
					x.AppliedRevision = old.AppliedRevision
					x.ApplyError = old.ApplyError
					x.CertExpiry = old.CertExpiry
				}
			}
			v = x
		}
	case "people":
		var x model.Person
		if err = decode(r, &x); err == nil {
			x.ID = id
			v = x
		}
	case "inbounds":
		var x model.Inbound
		if err = decode(r, &x); err == nil {
			x.ID = id
			v = x
		}
	case "outbounds":
		var x model.Outbound
		if err = decode(r, &x); err == nil {
			x.ID = id
			v = x
		}
	case "rules":
		var x model.Rule
		if err = decode(r, &x); err == nil {
			x.ID = id
			v = x
		}
	case "assignments":
		fail(w, 405, "assignment updates not supported; delete and recreate")
		return
	}
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err = s.validate(kind, id, v, true); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err = s.Store.Upsert(kind, id, v, true); err != nil {
		fail(w, 500, err.Error())
		return
	}
	jsonOut(w, 200, v)
}
func (s *Server) delete(w http.ResponseWriter, r *http.Request) {
	kind, id := r.PathValue("kind"), r.PathValue("id")
	if !allowedKind(kind) {
		fail(w, 404, "unknown resource")
		return
	}
	if err := s.validate(kind, id, nil, true); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err := s.Store.Delete(kind, id); err != nil {
		fail(w, 500, err.Error())
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}
func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	kind, id := r.PathValue("kind"), r.PathValue("id")
	if kind != "nodes" && kind != "people" {
		fail(w, 404, "not found")
		return
	}
	st, _ := s.Store.State()
	if !exists(st, kind, id) {
		fail(w, 404, "not found")
		return
	}
	token := random(32)
	if err := s.Store.SetSecret(kind, id, token); err != nil {
		fail(w, 500, err.Error())
		return
	}
	subscriptionURL := ""
	deployCommand := ""
	if kind == "people" {
		subscriptionURL = s.subURL(token)
	} else {
		deployCommand = s.agentDeployCommand(id, token)
	}
	jsonOut(w, 200, map[string]string{"token": token, "subscription_url": subscriptionURL, "deploy_command": deployCommand})
}
func (s *Server) agentDeployCommand(nodeID, token string) string {
	return fmt.Sprintf(`set -eu
if [ -d /opt/vps-proxy-console/.git ]; then
  git -C /opt/vps-proxy-console pull --ff-only
else
  git clone https://github.com/biologmder/vps-proxy-console.git /opt/vps-proxy-console
fi
umask 077
cat > /opt/vps-proxy-console/agent.env <<'VPC_AGENT_ENV'
PANEL_URL=%s
NODE_ID=%s
NODE_TOKEN=%s
DATA_DIR=/data
XRAY_BIN=/usr/local/bin/xray
VPC_AGENT_ENV
cd /opt/vps-proxy-console
docker compose -f docker-compose.agent.yml pull agent
docker compose -f docker-compose.agent.yml up -d
docker compose -f docker-compose.agent.yml ps`, s.PublicURL, nodeID, token)
}
func (s *Server) subURL(token string) string {
	if token == "" {
		return ""
	}
	return s.PublicURL + "/sub/" + token
}

func exists(st model.State, kind, id string) bool {
	switch kind {
	case "nodes":
		for _, x := range st.Nodes {
			if x.ID == id {
				return true
			}
		}
	case "people":
		for _, x := range st.People {
			if x.ID == id {
				return true
			}
		}
	case "inbounds":
		for _, x := range st.Inbounds {
			if x.ID == id {
				return true
			}
		}
	case "outbounds":
		for _, x := range st.Outbounds {
			if x.ID == id {
				return true
			}
		}
	case "rules":
		for _, x := range st.Rules {
			if x.ID == id {
				return true
			}
		}
	case "assignments":
		for _, x := range st.Assignments {
			if x.ID == id {
				return true
			}
		}
	}
	return false
}

func (s *Server) validate(kind, id string, v any, replacing bool) error {
	st, err := s.Store.State()
	if err != nil {
		return err
	}
	if replacing && !exists(st, kind, id) {
		return errors.New("not found")
	}
	if kind == "nodes" {
		st.Nodes = replace(st.Nodes, id, v, func(x model.Node) string { return x.ID })
	}
	if kind == "people" {
		st.People = replace(st.People, id, v, func(x model.Person) string { return x.ID })
	}
	if kind == "inbounds" {
		st.Inbounds = replace(st.Inbounds, id, v, func(x model.Inbound) string { return x.ID })
	}
	if kind == "outbounds" {
		st.Outbounds = replace(st.Outbounds, id, v, func(x model.Outbound) string { return x.ID })
	}
	if kind == "rules" {
		st.Rules = replace(st.Rules, id, v, func(x model.Rule) string { return x.ID })
	}
	if kind == "assignments" {
		st.Assignments = replace(st.Assignments, id, v, func(x model.Assignment) string { return x.ID })
	}
	for _, n := range st.Nodes {
		if n.Name == "" || n.Domain == "" {
			return errors.New("node requires name and domain")
		}
		if n.PrivateIP != "" {
			ip := net.ParseIP(n.PrivateIP)
			_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
			if ip == nil || (!ip.IsPrivate() && !cgnat.Contains(ip)) {
				return errors.New("private_ip must be a private IP address")
			}
		}
	}
	for _, p := range st.People {
		if p.Name == "" || p.QuotaBytes < 0 {
			return errors.New("person requires name and nonnegative quota")
		}
	}
	for _, in := range st.Inbounds {
		if !exists(st, "nodes", in.NodeID) {
			return errors.New("inbound node not found")
		}
		if in.Name == "" {
			return errors.New("inbound requires name")
		}
	}
	for _, out := range st.Outbounds {
		if !exists(st, "nodes", out.NodeID) {
			return errors.New("outbound node not found")
		}
	}
	assignmentKeys := map[string]bool{}
	for _, a := range st.Assignments {
		if !exists(st, "people", a.PersonID) || !exists(st, "inbounds", a.InboundID) {
			return errors.New("assignment references missing person/inbound")
		}
		key := a.PersonID + ":" + a.InboundID
		if assignmentKeys[key] {
			return errors.New("person already assigned to this inbound")
		}
		assignmentKeys[key] = true
		for _, in := range st.Inbounds {
			if in.ID == a.InboundID && (in.Protocol == "socks" || in.Protocol == "http") {
				return errors.New("landing inbounds cannot be assigned")
			}
		}
	}
	for _, r := range st.Rules {
		if !exists(st, "nodes", r.NodeID) {
			return errors.New("rule node not found")
		}
		if r.PersonID != "" && !exists(st, "people", r.PersonID) {
			return errors.New("rule person not found")
		}
		if r.InboundID != "" && !exists(st, "inbounds", r.InboundID) {
			return errors.New("rule inbound not found")
		}
		if r.InboundID != "" {
			for _, in := range st.Inbounds {
				if in.ID == r.InboundID && in.NodeID != r.NodeID {
					return errors.New("rule inbound belongs to another node")
				}
			}
		}
		for _, c := range r.CIDRs {
			if net.ParseIP(c) == nil {
				if _, _, e := net.ParseCIDR(c); e != nil && !strings.HasPrefix(c, "geoip:") {
					return fmt.Errorf("invalid IP/CIDR %q", c)
				}
			}
		}
		for _, d := range r.Domains {
			if d == "" || strings.ContainsAny(d, "\r\n ") {
				return fmt.Errorf("invalid domain rule %q", d)
			}
		}
	}
	for _, n := range st.Nodes {
		if _, err := xray.Compile(st, n.ID); err != nil {
			return err
		}
	}
	return nil
}

func replace[T any](items []T, id string, v any, key func(T) string) []T {
	out := make([]T, 0, len(items)+1)
	for _, x := range items {
		if key(x) != id {
			out = append(out, x)
		}
	}
	if v != nil {
		out = append(out, v.(T))
	}
	return out
}

func (s *Server) sync(w http.ResponseWriter, r *http.Request, nodeID string) {
	st, err := s.Store.State()
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	cfg, err := xray.Compile(st, nodeID)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	jsonOut(w, 200, cfg)
}
func (s *Server) report(w http.ResponseWriter, r *http.Request, nodeID string) {
	var rep model.Report
	if err := decode(r, &rep); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err := s.Store.Report(nodeID, rep); err != nil {
		fail(w, 400, err.Error())
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func (s *Server) subscription(w http.ResponseWriter, r *http.Request) {
	personID, err := s.Store.FindSecret("people", r.PathValue("token"))
	if err != nil {
		fail(w, 404, "subscription not found")
		return
	}
	st, err := s.Store.State()
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	var p *model.Person
	for i := range st.People {
		if st.People[i].ID == personID {
			p = &st.People[i]
			break
		}
	}
	if p == nil {
		fail(w, 404, "subscription not found")
		return
	}
	entries := subscription.Entries(st, *p)
	if len(entries) == 0 {
		fail(w, 403, "subscription inactive")
		return
	}
	expire := int64(0)
	if p.ExpiresAt != nil {
		expire = p.ExpiresAt.Unix()
	}
	w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d", p.UsedBytes, p.QuotaBytes, expire))
	w.Header().Set("Profile-Update-Interval", "24")
	if r.URL.Query().Get("format") == "mihomo" {
		b, err := subscription.Mihomo(entries)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		_, _ = w.Write(b)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(subscription.Raw(entries))
}

func (s *Server) Serve(addr string) error { return http.ListenAndServe(addr, s.Handler()) }

func parseInt(s string) int64 { v, _ := strconv.ParseInt(s, 10, 64); return v }
