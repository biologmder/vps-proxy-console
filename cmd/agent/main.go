package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/biologmder/vps-proxy-console/internal/model"
	"golang.org/x/crypto/acme/autocert"
)

type Agent struct {
	panel, nodeID, token, dir, xray string
	client                          *http.Client
	cert                            *autocert.Manager
	mu                              sync.Mutex
	allowed                         map[string]bool
	proc                            *exec.Cmd
	activeHash                      [32]byte
	failedHash                      [32]byte
	retryAfter                      time.Time
	totals                          map[string]int64
	revision                        int64
	applyError                      string
}

func env(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}
func required(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}
func main() {
	a := &Agent{panel: strings.TrimRight(required("PANEL_URL"), "/"), nodeID: required("NODE_ID"), token: required("NODE_TOKEN"), dir: env("DATA_DIR", "/data"), xray: env("XRAY_BIN", "/usr/local/bin/xray"), client: &http.Client{Timeout: 45 * time.Second}, allowed: map[string]bool{}, totals: map[string]int64{}}
	if !strings.HasPrefix(a.panel, "https://") && !strings.HasPrefix(a.panel, "http://127.0.0.1") {
		log.Fatal("PANEL_URL must use HTTPS")
	}
	if err := os.MkdirAll(filepath.Join(a.dir, "certs"), 0700); err != nil {
		log.Fatal(err)
	}
	a.cert = &autocert.Manager{Prompt: autocert.AcceptTOS, Cache: autocert.DirCache(filepath.Join(a.dir, "acme")), HostPolicy: func(_ context.Context, host string) error {
		a.mu.Lock()
		ok := a.allowed[host]
		a.mu.Unlock()
		if !ok {
			return fmt.Errorf("domain %s not configured", host)
		}
		return nil
	}}
	go func() { log.Printf("ACME HTTP challenge: %v", http.ListenAndServe(":80", a.cert.HTTPHandler(nil))) }()
	a.loadTotals()
	a.loadLastConfig()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	a.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			a.stopProcess()
			return
		case <-ticker.C:
			a.tick(ctx)
		}
	}
}

func (a *Agent) request(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return nil, e
		}
		reader = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, a.panel+path, reader)
	if err != nil {
		return nil, err
	}
	r.Header.Set("X-Node-ID", a.nodeID)
	r.Header.Set("Authorization", "Bearer "+a.token)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return a.client.Do(r)
}
func (a *Agent) tick(ctx context.Context) {
	r, err := a.request(ctx, "GET", "/agent/v1/sync", nil)
	if err != nil {
		log.Printf("panel unavailable: %v", err)
		a.collect()
		return
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		log.Printf("sync status: %s", r.Status)
		a.collect()
		return
	}
	var desired model.Desired
	if err = json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&desired); err != nil {
		log.Printf("sync JSON: %v", err)
		return
	}
	a.mu.Lock()
	a.allowed = map[string]bool{}
	for _, d := range desired.TLSNames {
		a.allowed[d] = true
	}
	a.mu.Unlock()
	certRenewed := false
	for _, d := range desired.TLSNames {
		old, _ := os.ReadFile(filepath.Join(a.dir, "certs", d+".crt"))
		if err := a.ensureCertificate(d); err != nil {
			a.applyError = err.Error()
			log.Printf("certificate %s: %v", d, err)
			a.collect()
			a.report(ctx)
			return
		}
		current, _ := os.ReadFile(filepath.Join(a.dir, "certs", d+".crt"))
		if !bytes.Equal(old, current) {
			certRenewed = true
		}
	}
	h := sha256.Sum256(desired.Config)
	if a.proc != nil && a.proc.ProcessState != nil {
		a.proc = nil
		a.activeHash = [32]byte{}
	}
	if certRenewed {
		a.activeHash = [32]byte{}
		a.failedHash = [32]byte{}
	}
	if h != a.activeHash {
		if h != a.failedHash || time.Now().After(a.retryAfter) {
			a.collect()
			if err := a.apply(desired.Config); err != nil {
				a.applyError = err.Error()
				a.failedHash = h
				a.retryAfter = time.Now().Add(5 * time.Minute)
				log.Printf("apply: %v", err)
			} else {
				a.activeHash = h
				a.failedHash = [32]byte{}
				a.revision = desired.Revision
				a.applyError = ""
				log.Printf("applied revision %d", desired.Revision)
			}
		}
	}
	if h == a.activeHash {
		a.revision = desired.Revision
	}
	a.collect()
	a.report(ctx)
}

func (a *Agent) ensureCertificate(domain string) error {
	crt := filepath.Join(a.dir, "certs", domain+".crt")
	key := filepath.Join(a.dir, "certs", domain+".key")
	if b, e := os.ReadFile(crt); e == nil {
		block, _ := pem.Decode(b)
		if block != nil {
			cert, e := x509.ParseCertificate(block.Bytes)
			if e == nil && time.Until(cert.NotAfter) > 14*24*time.Hour {
				return nil
			}
		}
	}
	c, e := a.cert.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
	if e != nil {
		return e
	}
	var certPEM []byte
	for _, der := range c.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	private, e := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if e != nil {
		return e
	}
	if e = writeAtomic(crt, certPEM, 0600); e != nil {
		return e
	}
	if e = writeAtomic(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); e != nil {
		return e
	}
	return nil
}
func writeAtomic(path string, b []byte, perm os.FileMode) error {
	temp := path + ".tmp"
	if err := os.WriteFile(temp, b, perm); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func (a *Agent) apply(config []byte) error {
	candidate := filepath.Join(a.dir, "candidate.json")
	if err := writeAtomic(candidate, config, 0600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.xray, "run", "-test", "-c", candidate)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("xray config test: %s: %w", strings.TrimSpace(string(b)), err)
	}
	active := filepath.Join(a.dir, "active.json")
	previous := filepath.Join(a.dir, "previous.json")
	old, _ := os.ReadFile(active)
	a.stopProcess()
	if len(old) > 0 {
		_ = writeAtomic(previous, old, 0600)
	}
	if err := writeAtomic(active, config, 0600); err != nil {
		return err
	}
	if err := a.startProcess(active); err != nil {
		if len(old) > 0 {
			_ = writeAtomic(active, old, 0600)
			_ = a.startProcess(active)
		}
		return fmt.Errorf("new Xray failed; previous config restored: %w", err)
	}
	return nil
}
func (a *Agent) startProcess(path string) error {
	cmd := exec.Command(a.xray, "run", "-c", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return fmt.Errorf("xray exited: %w", err)
	case <-time.After(2 * time.Second):
		a.proc = cmd
		return nil
	}
}
func (a *Agent) stopProcess() {
	if a.proc != nil && a.proc.Process != nil {
		_ = a.proc.Process.Signal(syscall.SIGTERM)
		time.Sleep(300 * time.Millisecond)
		_ = a.proc.Process.Kill()
		a.proc = nil
	}
}
func (a *Agent) loadLastConfig() {
	path := filepath.Join(a.dir, "active.json")
	b, e := os.ReadFile(path)
	if e != nil {
		return
	}
	if e = a.startProcess(path); e != nil {
		log.Printf("last config failed: %v", e)
		return
	}
	a.activeHash = sha256.Sum256(b)
}

func (a *Agent) loadTotals() {
	b, e := os.ReadFile(filepath.Join(a.dir, "usage.json"))
	if e == nil {
		_ = json.Unmarshal(b, &a.totals)
	}
}
func (a *Agent) collect() {
	if a.proc == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, a.xray, "api", "statsquery", "--server=127.0.0.1:10085", "-pattern=user>>>", "-reset=true").Output()
	if err != nil {
		log.Printf("stats: %v", err)
		return
	}
	var data struct {
		Stat []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"stat"`
	}
	if err = json.Unmarshal(b, &data); err != nil {
		log.Printf("stats JSON: %v", err)
		return
	}
	for _, entry := range data.Stat {
		parts := strings.Split(entry.Name, ">>>")
		if len(parts) != 4 || parts[0] != "user" {
			continue
		}
		email := parts[1]
		if !strings.HasPrefix(email, "a-") || !strings.HasSuffix(email, "@local") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(email, "a-"), "@local")
		var n int64
		if _, err = fmt.Sscan(entry.Value, &n); err == nil && n > 0 {
			a.totals[id] += n
		}
	}
	if err := writeAtomic(filepath.Join(a.dir, "usage.json"), mustJSON(a.totals), 0600); err != nil {
		log.Printf("save usage: %v", err)
	}
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func (a *Agent) report(ctx context.Context) {
	expiry := map[string]time.Time{}
	a.mu.Lock()
	for domain := range a.allowed {
		b, e := os.ReadFile(filepath.Join(a.dir, "certs", domain+".crt"))
		if e != nil {
			continue
		}
		block, _ := pem.Decode(b)
		if block == nil {
			continue
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e == nil {
			expiry[domain] = cert.NotAfter
		}
	}
	a.mu.Unlock()
	r, err := a.request(ctx, "POST", "/agent/v1/report", model.Report{Revision: a.revision, ApplyError: a.applyError, Totals: a.totals, CertExpiry: expiry})
	if err != nil {
		log.Printf("report: %v", err)
		return
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1000))
		log.Printf("report status %s: %s", r.Status, b)
	}
}
