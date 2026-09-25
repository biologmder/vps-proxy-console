package store

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/biologmder/vps-proxy-console/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct {
	DB *sql.DB
	mu sync.Mutex
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{
		`PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout=5000`,
		`CREATE TABLE IF NOT EXISTS records(kind TEXT NOT NULL,id TEXT NOT NULL,data BLOB NOT NULL,PRIMARY KEY(kind,id))`,
		`CREATE TABLE IF NOT EXISTS secrets(kind TEXT NOT NULL,id TEXT NOT NULL,hash TEXT NOT NULL,PRIMARY KEY(kind,id))`,
		`CREATE TABLE IF NOT EXISTS usage(assignment_id TEXT PRIMARY KEY,person_id TEXT NOT NULL,node_id TEXT NOT NULL,total INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value INTEGER NOT NULL)`,
		`INSERT OR IGNORE INTO meta(key,value) VALUES('revision',1)`,
	} {
		if _, err = db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	return &Store{DB: db}, nil
}

func Hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func (s *Store) SetSecret(kind, id, token string) error {
	_, err := s.DB.Exec(`INSERT INTO secrets(kind,id,hash) VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET hash=excluded.hash`, kind, id, Hash(token))
	return err
}
func (s *Store) CheckSecret(kind, id, token string) bool {
	if token == "" {
		return false
	}
	var h string
	if s.DB.QueryRow(`SELECT hash FROM secrets WHERE kind=? AND id=?`, kind, id).Scan(&h) != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h), []byte(Hash(token))) == 1
}
func (s *Store) FindSecret(kind, token string) (string, error) {
	if token == "" {
		return "", errors.New("empty token")
	}
	rows, err := s.DB.Query(`SELECT id FROM secrets WHERE kind=? AND hash=?`, kind, Hash(token))
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if rows.Next() {
		var id string
		err = rows.Scan(&id)
		return id, err
	}
	return "", sql.ErrNoRows
}

func (s *Store) Upsert(kind, id string, v any, bump bool) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO records(kind,id,data) VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data`, kind, id, b); err != nil {
		return err
	}
	if bump {
		if _, err = tx.Exec(`UPDATE meta SET value=value+1 WHERE key='revision'`); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Delete(kind, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM records WHERE kind=? AND id=?`, kind, id); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM secrets WHERE kind=? AND id=?`, kind, id); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE meta SET value=value+1 WHERE key='revision'`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) State() (model.State, error) {
	var state model.State
	if err := s.DB.QueryRow(`SELECT value FROM meta WHERE key='revision'`).Scan(&state.Revision); err != nil {
		return state, err
	}
	rows, err := s.DB.Query(`SELECT kind,data FROM records ORDER BY kind,id`)
	if err != nil {
		return state, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var b []byte
		if err = rows.Scan(&kind, &b); err != nil {
			return state, err
		}
		switch kind {
		case "nodes":
			var x model.Node
			if err = json.Unmarshal(b, &x); err == nil {
				state.Nodes = append(state.Nodes, x)
			}
		case "people":
			var x model.Person
			if err = json.Unmarshal(b, &x); err == nil {
				state.People = append(state.People, x)
			}
		case "inbounds":
			var x model.Inbound
			if err = json.Unmarshal(b, &x); err == nil {
				state.Inbounds = append(state.Inbounds, x)
			}
		case "outbounds":
			var x model.Outbound
			if err = json.Unmarshal(b, &x); err == nil {
				state.Outbounds = append(state.Outbounds, x)
			}
		case "rules":
			var x model.Rule
			if err = json.Unmarshal(b, &x); err == nil {
				state.Rules = append(state.Rules, x)
			}
		case "assignments":
			var x model.Assignment
			if err = json.Unmarshal(b, &x); err == nil {
				state.Assignments = append(state.Assignments, x)
			}
		}
		if err != nil {
			return state, fmt.Errorf("%s: %w", kind, err)
		}
	}
	if err = rows.Err(); err != nil {
		return state, err
	}
	_ = rows.Close()
	personTotals := map[string]int64{}
	rows2, err := s.DB.Query(`SELECT person_id,total FROM usage`)
	if err != nil {
		return state, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var id string
		var n int64
		if err = rows2.Scan(&id, &n); err != nil {
			return state, err
		}
		personTotals[id] += n
	}
	if err = rows2.Err(); err != nil {
		return state, err
	}
	for i := range state.People {
		state.People[i].UsedBytes = personTotals[state.People[i].ID]
	}
	return state, nil
}

// Report applies monotonic per-assignment counters. Replayed reports cannot double-count.
func (s *Store) Report(nodeID string, r model.Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var b []byte
	if err = tx.QueryRow(`SELECT data FROM records WHERE kind='nodes' AND id=?`, nodeID).Scan(&b); err != nil {
		return err
	}
	var node model.Node
	if err = json.Unmarshal(b, &node); err != nil {
		return err
	}
	node.LastSeen = time.Now().UTC()
	node.AppliedRevision = r.Revision
	node.ApplyError = r.ApplyError
	node.CertExpiry = r.CertExpiry
	b, _ = json.Marshal(node)
	if _, err = tx.Exec(`UPDATE records SET data=? WHERE kind='nodes' AND id=?`, b, nodeID); err != nil {
		return err
	}
	for id, total := range r.Totals {
		if total < 0 {
			return errors.New("negative counter")
		}
		var ab []byte
		err = tx.QueryRow(`SELECT data FROM records WHERE kind='assignments' AND id=?`, id).Scan(&ab)
		if errors.Is(err, sql.ErrNoRows) {
			var owner string
			if tx.QueryRow(`SELECT node_id FROM usage WHERE assignment_id=?`, id).Scan(&owner) == nil && owner == nodeID {
				_, err = tx.Exec(`UPDATE usage SET total=MAX(total,?) WHERE assignment_id=?`, total, id)
				if err != nil {
					return err
				}
			}
			continue
		}
		if err != nil {
			return err
		}
		var a model.Assignment
		if err = json.Unmarshal(ab, &a); err != nil {
			return err
		}
		var ib []byte
		if err = tx.QueryRow(`SELECT data FROM records WHERE kind='inbounds' AND id=?`, a.InboundID).Scan(&ib); err != nil {
			return err
		}
		var in model.Inbound
		if err = json.Unmarshal(ib, &in); err != nil {
			return err
		}
		if in.NodeID != nodeID || in.Protocol == "socks" || in.Protocol == "http" {
			return errors.New("counter not owned by node")
		}
		if _, err = tx.Exec(`INSERT INTO usage(assignment_id,person_id,node_id,total) VALUES(?,?,?,?) ON CONFLICT(assignment_id) DO UPDATE SET total=MAX(total,excluded.total)`, id, a.PersonID, nodeID, total); err != nil {
			return err
		}
	}
	return tx.Commit()
}
