package scan

import (
	"database/sql"
	"strconv"
	"strings"
	"sync"

	"github.com/asi-agh/asi/internal/ports"
	"github.com/asi-agh/asi/internal/sig"
	"github.com/asi-agh/asi/internal/store"
)

// Reguły klasy: każda reguła ma wagę (punkty) i włącznik. Klasa usługi = suma wag dopasowanych reguł (maks. 100).
// Rodzaje: signature (sygnatura detekcyjna, waga × pewność), heuristic (reguły ogólne, np. wygasły certyfikat),
// port (otwarty port; nowe porty dopisywane automatycznie z wagą 0 do oceny przez analityka).

type Rule struct {
	ID       int64  `json:"id"`
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	Name     string `json:"name"`
	Weight   int    `json:"weight"`
	Enabled  bool   `json:"enabled"`
	Auto     bool   `json:"auto"`
	Reviewed bool   `json:"reviewed"`
	Created  string `json:"created_at"`
	Matches  int    `json:"matches"`
}

// Heuristics: reguły ogólne (domyślne wagi = dotychczasowe stałe w kodzie).
var Heuristics = []struct {
	Key, Name string
	Weight    int
}{
	{"cert-wygasly", "Certyfikat TLS wygasł", 10},
	{"cert-wygasa", "Certyfikat TLS wygasa w ciągu 30 dni", 4},
	{"cert-self-signed", "Certyfikat self-signed", 4},
	{"http-obok-https", "HTTP odsłonięty obok HTTPS (bez przekierowania): warto zamknąć lub przekierować", 6},
	{"wolna-odpowiedz", "Wolna odpowiedź HTTP (≥ 500 ms): opóźnienie, przeciążenie lub pośrednik", 2},
	{"tls-bez-certyfikatu", "Port TLS bez certyfikatu dla adresu IP (wymaga nazwy hosta / SNI)", 4},
	{"stary-tls", "Stary protokół TLS 1.0/1.1", 6},
	{"logowanie-bez-tls", "Formularz logowania bez TLS", 12},
	{"wersja-server", "Wersja w nagłówku Server", 3},
	{"wersja-x-powered-by", "Nagłówek X-Powered-By", 3},
	{"ciasteczko-bez-httponly", "Ciasteczko sesyjne bez HttpOnly", 3},
	{"niestandardowy-port-http", "HTTP na niestandardowym porcie", 4},
	{"znana-wersja", "Usługa ujawnia produkt i wersję", 1},
}

type RuleSet struct {
	mu      sync.RWMutex
	byKey   map[string]*Rule // kind|key
	enabled int
}

var rules = &RuleSet{byKey: map[string]*Rule{}}

func ActiveRules() *RuleSet { return rules }

func rk(kind, key string) string { return kind + "|" + key }

// weight: waga reguły (0, gdy wyłączona); ok=false, gdy reguły nie ma (używamy wartości domyślnej).
func (r *RuleSet) weight(kind, key string) (int, bool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	x := r.byKey[rk(kind, key)]
	if x == nil {
		return 0, false, false
	}
	if !x.Enabled {
		return 0, true, false
	}
	return x.Weight, true, true
}

func (r *RuleSet) Enabled() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled
}

func (r *RuleSet) has(kind, key string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byKey[rk(kind, key)] != nil
}

// LoadRules: odczyt reguł z bazy do pamięci.
func LoadRules(db *sql.DB) error {
	rows, err := db.Query(`SELECT id,kind,key,name,weight,enabled,auto,reviewed,created_at FROM scoring_rules`)
	if err != nil {
		return err
	}
	defer rows.Close()
	m := map[string]*Rule{}
	en := 0
	for rows.Next() {
		x := &Rule{}
		var e, a, rv int
		if err := rows.Scan(&x.ID, &x.Kind, &x.Key, &x.Name, &x.Weight, &e, &a, &rv, &x.Created); err != nil {
			return err
		}
		x.Enabled, x.Auto, x.Reviewed = e == 1, a == 1, rv == 1
		m[rk(x.Kind, x.Key)] = x
		if x.Enabled && x.Weight > 0 {
			en++ // pokrycie liczone względem reguł, które mają znaczenie (waga > 0)
		}
	}
	rules.mu.Lock()
	rules.byKey, rules.enabled = m, en
	rules.mu.Unlock()
	return nil
}

// SyncRules: reguły dla wszystkich sygnatur (waga domyślna = interest sygnatury) i reguł ogólnych.
func SyncRules(db *sql.DB, sigs []sig.Signature) error {
	now := store.Now()
	for _, s := range sigs {
		if _, err := db.Exec(`INSERT OR IGNORE INTO scoring_rules(kind,key,name,weight,enabled,auto,reviewed,created_at) VALUES('signature',?,?,?,1,0,1,?)`,
			s.ID, s.Name, s.Interest, now); err != nil {
			return err
		}
		_, _ = db.Exec(`UPDATE scoring_rules SET name=? WHERE kind='signature' AND key=?`, s.Name, s.ID)
	}
	// porty wykryte wcześniej (inwentarz) jako reguły „nowe, do oceny” z wagą 0
	_, _ = db.Exec(`INSERT OR IGNORE INTO scoring_rules(kind,key,name,weight,enabled,auto,reviewed,created_at)
SELECT 'port', s.proto||'/'||s.port, 'Port '||s.proto||'/'||s.port||COALESCE(' ('||NULLIF((SELECT o.service FROM observations o WHERE o.id=s.last_obs_id),'')||')',''),
0, 1, 1, 0, MIN(s.first_seen) FROM services s GROUP BY s.proto, s.port`)
	for _, h := range Heuristics {
		if _, err := db.Exec(`INSERT OR IGNORE INTO scoring_rules(kind,key,name,weight,enabled,auto,reviewed,created_at) VALUES('heuristic',?,?,?,1,0,1,?)`,
			h.Key, h.Name, h.Weight, now); err != nil {
			return err
		}
	}
	return LoadRules(db)
}

func portKey(proto string, port int) string { return proto + "/" + strconv.Itoa(port) }

// ensurePortRules: każdy nowy otwarty port dopisywany automatycznie jako reguła z wagą 0 („nowa, do oceny”).
func ensurePortRules(tx execer, obs []*Observation) {
	added := false
	for _, o := range obs {
		k := portKey(o.Proto, o.Port)
		if rules.has("port", k) {
			continue
		}
		name := "Port " + k
		if o.Service != "" {
			name += " (" + o.Service + ")"
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO scoring_rules(kind,key,name,weight,enabled,auto,reviewed,created_at) VALUES('port',?,?,0,1,1,0,?)`,
			k, name, store.Now()); err == nil {
			rules.mu.Lock()
			rules.byKey[rk("port", k)] = &Rule{Kind: "port", Key: k, Name: name, Enabled: true, Auto: true}
			rules.mu.Unlock()
			added = true
		}
	}
	_ = added
}

// RuleKeyOfFlag: flagi heurystyk → klucz reguły.
func ruleName(kind, key string) string {
	rules.mu.RLock()
	defer rules.mu.RUnlock()
	if x := rules.byKey[rk(kind, key)]; x != nil {
		return x.Name
	}
	return key
}

var _ = strings.TrimSpace

// autoAddPorts: opcja konfiguracji (domyślnie wyłączona). Dopisuje do listy portów skanu porty wykryte w sieci
// (reguły portów), ale WYŁĄCZNIE te, które mieszczą się w liście portów zatwierdzonych przez administratora
// (ustawienie allowed_ports). Bez tej listy nic nie jest dopisywane.
func (e *Engine) autoAddPorts(cfg *Config) string {
	allowedStr := e.S.GetSetting("allowed_ports")
	if strings.TrimSpace(allowedStr) == "" {
		e.logf("konfiguracja %q: auto-dopisywanie portów pominięte (brak listy portów zatwierdzonych)", cfg.Name)
		return ""
	}
	allowed, err := ports.Parse(allowedStr)
	if err != nil {
		return ""
	}
	cur, err := ports.Parse(cfg.Ports)
	if err != nil {
		return ""
	}
	rules.mu.RLock()
	var add []string
	for _, x := range rules.byKey {
		if x.Kind != "port" {
			continue
		}
		parts := strings.SplitN(x.Key, "/", 2)
		if len(parts) != 2 {
			continue
		}
		p, err := strconv.Atoi(parts[1])
		if err != nil || !allowed.Contains(parts[0], p) || cur.Contains(parts[0], p) {
			continue
		}
		pre := "T:"
		if parts[0] == "udp" {
			pre = "U:"
		}
		add = append(add, pre+parts[1])
	}
	rules.mu.RUnlock()
	if len(add) == 0 {
		return ""
	}
	merged, err := ports.Parse(cur.NmapArg() + "," + strings.Join(add, ","))
	if err != nil {
		return ""
	}
	cfg.Ports = merged.String()
	_, _ = e.S.DB.Exec(`UPDATE scan_configs SET ports=? WHERE id=?`, cfg.Ports, cfg.ID)
	return strings.Join(add, ",")
}

// Rescore: przeliczenie klasy wszystkich zapisanych obserwacji po zmianie reguł (bez ruchu sieciowego).
func (e *Engine) Rescore() (int, error) {
	obs, err := ListObs(e.S, ``, true)
	if err != nil {
		return 0, err
	}
	tx, err := e.S.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	ovs, _ := LoadOverrides(e.S.DB)
	for _, o := range obs {
		Score(o)
		if x, ok := ovs[SvcEntity(o.IP, o.Port, o.Proto)]; ok && x.Interest != nil {
			o.Interest = max(0, min(100, *x.Interest)) // klasa ustawiona ręcznie nie jest nadpisywana przez Rescore
		}
		if _, err := tx.Exec(`UPDATE observations SET interest=?, flags=?, rules=? WHERE id=?`, o.Interest, store.ToJSON(o.Flags), store.ToJSON(o.Rules), o.ID); err != nil {
			return 0, err
		}
	}
	return len(obs), tx.Commit()
}
