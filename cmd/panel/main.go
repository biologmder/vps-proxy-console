package main

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/biologmder/vps-proxy-console/internal/panel"
	"github.com/biologmder/vps-proxy-console/internal/store"
)

func env(k, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
}
func main() {
	path := env("DATABASE_PATH", "/data/panel.db")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		log.Fatal(err)
	}
	st, err := store.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer st.DB.Close()
	s, err := panel.New(st, os.Getenv("ADMIN_PASSWORD"), env("PUBLIC_URL", "http://127.0.0.1:8080"), env("WEB_DIR", "/app/web"))
	if err != nil {
		log.Fatal(err)
	}
	s.TelegramToken = os.Getenv("TELEGRAM_BOT_TOKEN")
	s.TelegramChat = os.Getenv("TELEGRAM_CHAT_ID")
	if s.TelegramToken != "" && s.TelegramChat != "" {
		go alerts(s)
	}
	log.Printf("panel listening on %s", env("LISTEN_ADDR", ":8080"))
	log.Fatal(s.Serve(env("LISTEN_ADDR", ":8080")))
}

func alerts(s *panel.Server) {
	seen := map[string]bool{}
	for {
		time.Sleep(time.Minute)
		st, err := s.Store.State()
		if err != nil {
			log.Printf("alerts: %v", err)
			continue
		}
		active := map[string]bool{}
		for _, n := range st.Nodes {
			if !n.LastSeen.IsZero() && time.Since(n.LastSeen) > 90*time.Second {
				key := "offline:" + n.ID
				active[key] = true
				if !seen[key] {
					send(s, "节点离线："+n.Name)
				}
			}
			if n.ApplyError != "" {
				key := "apply:" + n.ID + ":" + n.ApplyError
				active[key] = true
				if !seen[key] {
					send(s, "节点配置应用失败："+n.Name+" — "+n.ApplyError)
				}
			}
			for domain, expiry := range n.CertExpiry {
				if time.Until(expiry) < 14*24*time.Hour {
					key := "cert:" + domain
					active[key] = true
					if !seen[key] {
						send(s, "证书将在 14 天内到期："+domain+"，到期时间 "+expiry.Format(time.RFC3339))
					}
				}
			}
		}
		for _, p := range st.People {
			if p.QuotaBytes > 0 && p.UsedBytes*100 >= p.QuotaBytes*80 {
				key := "quota:" + p.ID
				active[key] = true
				if !seen[key] {
					send(s, "流量额度达到 80%："+p.Name+"（"+strconv.FormatInt(p.UsedBytes, 10)+"/"+strconv.FormatInt(p.QuotaBytes, 10)+" 字节）")
				}
			}
		}
		seen = active
	}
}
func send(s *panel.Server, text string) {
	endpoint := "https://api.telegram.org/bot" + s.TelegramToken + "/sendMessage"
	client := &http.Client{Timeout: 10 * time.Second}
	r, err := client.PostForm(endpoint, url.Values{"chat_id": {s.TelegramChat}, "text": {text}})
	if err != nil {
		log.Printf("Telegram: %v", err)
		return
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		log.Printf("Telegram status: %s", r.Status)
	}
}
