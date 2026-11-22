// Package store: baza SQLite (WAL) z szyfrowaniem pól wrażliwych przez secure.Box.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/asi-agh/asi/internal/secure"
)

type Store struct {
	DB  *sql.DB
	Box *secure.Box
}

func Now() string { return time.Now().UTC().Format(time.RFC3339) }

func Open(path string, box *secure.Box) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	s := &Store{DB: db, Box: box}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS roles(
  id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, description TEXT DEFAULT '', builtin INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS role_permissions(
  role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE, perm TEXT NOT NULL, PRIMARY KEY(role_id, perm));
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL,
  role_id INTEGER REFERENCES roles(id), disabled INTEGER DEFAULT 0, created_at TEXT, last_login TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS targets(
  id INTEGER PRIMARY KEY, value TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, tags TEXT DEFAULT '[]',
  note_enc TEXT DEFAULT '', enabled INTEGER DEFAULT 1, source TEXT DEFAULT 'manual',
  created_by TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS scan_configs(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, target_tags TEXT DEFAULT '[]', ports TEXT DEFAULT '',
  discovery_ports TEXT DEFAULT '22,80,443,3389,8080', rate INTEGER DEFAULT 1000, http_rps INTEGER DEFAULT 20,
  workers INTEGER DEFAULT 4, chunk_target_sec INTEGER DEFAULT 60, host_timeout_sec INTEGER DEFAULT 120,
  retries INTEGER DEFAULT 1, retry_unstable INTEGER DEFAULT 1, http_probe INTEGER DEFAULT 1,
  version_intensity INTEGER DEFAULT 5, gone_after INTEGER DEFAULT 3, excludes TEXT DEFAULT '',
  sched_enabled INTEGER DEFAULT 0, sched_every_min INTEGER DEFAULT 1440, win_start TEXT DEFAULT '00:00',
  win_end TEXT DEFAULT '23:59', win_days TEXT DEFAULT '1234567', next_run TEXT DEFAULT '',
  created_by TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY, config_id INTEGER, name TEXT, status TEXT NOT NULL, ports TEXT DEFAULT '',
  config_snapshot TEXT DEFAULT '{}', hostnames TEXT DEFAULT '{}', total_ips INTEGER DEFAULT 0, done_ips INTEGER DEFAULT 0,
  live_hosts INTEGER DEFAULT 0, open_services INTEGER DEFAULT 0, created_at TEXT, started_at TEXT DEFAULT '',
  finished_at TEXT DEFAULT '', elapsed_ms INTEGER DEFAULT 0, windows INTEGER DEFAULT 0, triggered_by TEXT DEFAULT '',
  note_enc TEXT DEFAULT '', error TEXT DEFAULT '', source TEXT DEFAULT 'scan');
CREATE INDEX IF NOT EXISTS scans_cfg ON scans(config_id, id);
CREATE TABLE IF NOT EXISTS scan_blocks(
  id INTEGER PRIMARY KEY, scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE, idx INTEGER,
  ips TEXT NOT NULL, size INTEGER, status TEXT DEFAULT 'pending', job INTEGER DEFAULT 0,
  duration_ms INTEGER DEFAULT 0, live INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS blocks_scan ON scan_blocks(scan_id, status, idx);
CREATE TABLE IF NOT EXISTS scan_jobs(
  id INTEGER PRIMARY KEY, scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE, ips INTEGER, live INTEGER,
  services INTEGER, started_at TEXT, duration_ms INTEGER, worker INTEGER, status TEXT);
CREATE TABLE IF NOT EXISTS scan_hosts(
  scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE, ip TEXT NOT NULL, alive INTEGER NOT NULL,
  hostname TEXT DEFAULT '', reason TEXT DEFAULT '', retried INTEGER DEFAULT 0, PRIMARY KEY(scan_id, ip));
CREATE TABLE IF NOT EXISTS observations(
  id INTEGER PRIMARY KEY, scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE, ip TEXT NOT NULL,
  port INTEGER NOT NULL, proto TEXT NOT NULL, state TEXT DEFAULT 'open', service TEXT DEFAULT '',
  product TEXT DEFAULT '', version TEXT DEFAULT '', tls INTEGER DEFAULT 0, http_status INTEGER DEFAULT 0,
  techs TEXT DEFAULT '[]', flags TEXT DEFAULT '[]', interest INTEGER DEFAULT 0, data_enc TEXT DEFAULT '',
  fingerprint TEXT DEFAULT '', edited INTEGER DEFAULT 0, edited_by TEXT DEFAULT '',
  UNIQUE(scan_id, ip, port, proto));
CREATE INDEX IF NOT EXISTS obs_key ON observations(ip, port, proto);
CREATE TABLE IF NOT EXISTS hosts(
  ip TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, seen_count INTEGER DEFAULT 0, scan_count INTEGER DEFAULT 0,
  miss_streak INTEGER DEFAULT 0, state TEXT DEFAULT 'active', history TEXT DEFAULT '', hours_seen TEXT DEFAULT '[]',
  hours_scanned TEXT DEFAULT '[]', hostname TEXT DEFAULT '', last_scan_id INTEGER DEFAULT 0, state_changed TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS services(
  ip TEXT, port INTEGER, proto TEXT, first_seen TEXT, last_seen TEXT, miss_streak INTEGER DEFAULT 0,
  state TEXT DEFAULT 'active', history TEXT DEFAULT '', last_obs_id INTEGER DEFAULT 0, PRIMARY KEY(ip, port, proto));
CREATE TABLE IF NOT EXISTS annotations(
  entity TEXT PRIMARY KEY, tags TEXT DEFAULT '[]', note_enc TEXT DEFAULT '', owner TEXT DEFAULT '',
  criticality INTEGER DEFAULT 0, false_positive INTEGER DEFAULT 0, tech_override TEXT DEFAULT '',
  updated_by TEXT DEFAULT '', updated_at TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS signatures(
  id INTEGER PRIMARY KEY, sid TEXT UNIQUE NOT NULL, name TEXT, category TEXT, enabled INTEGER DEFAULT 1,
  builtin INTEGER DEFAULT 0, body TEXT NOT NULL, created_by TEXT DEFAULT '', updated_at TEXT);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts TEXT, username TEXT, action TEXT, entity TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value_enc TEXT);
CREATE TABLE IF NOT EXISTS revoked_tokens(jti TEXT PRIMARY KEY, expires TEXT);
CREATE TABLE IF NOT EXISTS technologies(
  id TEXT PRIMARY KEY, name TEXT, category TEXT, first_seen TEXT, first_scan_id INTEGER, last_seen TEXT, last_scan_id INTEGER,
  sightings INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS dojo_pushes(
  id INTEGER PRIMARY KEY, ts TEXT, username TEXT, scan_id INTEGER, mode TEXT, test_title TEXT, test_id INTEGER DEFAULT 0,
  sent INTEGER, created INTEGER DEFAULT 0, closed INTEGER DEFAULT 0, reactivated INTEGER DEFAULT 0, untouched INTEGER DEFAULT 0,
  total_after INTEGER DEFAULT 0, error TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS scoring_rules(
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL, name TEXT DEFAULT '', weight INTEGER DEFAULT 0,
  enabled INTEGER DEFAULT 1, auto INTEGER DEFAULT 0, reviewed INTEGER DEFAULT 1, created_at TEXT DEFAULT '', UNIQUE(kind, key));
`

func (s *Store) migrate() error {
	if _, err := s.DB.Exec(schema); err != nil {
		return err
	}
	var hadTechStatus int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('technologies') WHERE name='status'`).Scan(&hadTechStatus)
	var hadTag int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('scans') WHERE name='tag'`).Scan(&hadTag)
	// migracje kolumn dodanych po pierwszej wersji schematu
	for _, c := range [][3]string{
		{"hosts", "last_checked", "TEXT DEFAULT ''"},
		{"scans", "explicit", "TEXT DEFAULT '[]'"},
		{"scan_configs", "retry_enabled", "INTEGER DEFAULT 0"},
		{"scan_configs", "retry_win_start", "TEXT DEFAULT '07:00'"},
		{"scan_configs", "retry_win_end", "TEXT DEFAULT '21:00'"},
		{"scan_configs", "retry_batch", "INTEGER DEFAULT 16"},
		{"scan_configs", "retry_every_min", "INTEGER DEFAULT 10"},
		{"scan_configs", "retry_next", "TEXT DEFAULT ''"},
		{"scan_configs", "retry_pause_sec", "INTEGER DEFAULT 15"},
		{"scan_configs", "dojo_auto", "INTEGER DEFAULT 0"},
		{"scan_configs", "dojo_min_interest", "INTEGER DEFAULT 20"},
		{"observations", "seen_at", "TEXT DEFAULT ''"},
		{"observations", "rules", "TEXT DEFAULT '[]'"},
		{"scan_configs", "auto_add_ports", "INTEGER DEFAULT 0"},
		{"observations", "response_ms", "INTEGER DEFAULT 0"},
		{"scans", "tag", "TEXT DEFAULT ''"},
		{"technologies", "status", "TEXT DEFAULT 'new'"},
		{"technologies", "decision", "TEXT DEFAULT ''"},
		{"technologies", "reviewed_by", "TEXT DEFAULT ''"},
		{"technologies", "reviewed_at", "TEXT DEFAULT ''"},
		{"users", "sessions_after", "INTEGER DEFAULT 0"}, // (nieużywane, zastąpione token_gen)
		{"users", "token_gen", "INTEGER DEFAULT 0"},      // generacja sesji: zmiana hasła podbija licznik, starsze tokeny są nieważne
	} {
		if err := s.addColumn(c[0], c[1], c[2]); err != nil {
			return err
		}
	}
	if hadTechStatus == 0 {
		s.TechBaseline() // istniejący katalog: inwentarz z pierwszej godziny = znany, reszta do przejrzenia
	}
	if hadTag == 0 {
		// jednorazowo: nazwy nadane przy uruchomieniu (nie automatyczne „<reguła> · data” ani doskanowanie) stają się tagami
		_, _ = s.DB.Exec(`UPDATE scans SET tag=name WHERE source='scan' AND name NOT LIKE 'Doskanowanie · %'
AND name NOT GLOB '* · [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]'`)
	}
	// korekta wpisów historii DefectDojo zapisanych z podwojonymi licznikami (błąd sumowania, poprawiony 21.11)
	_, _ = s.DB.Exec(`UPDATE dojo_pushes SET created=created/2, closed=closed/2, reactivated=reactivated/2, untouched=untouched/2
WHERE mode LIKE 'reimport%' AND untouched+created > sent`)
	// starsze obserwacje bez czasu wykrycia: czas startu skanu
	_, _ = s.DB.Exec(`UPDATE observations SET seen_at=(SELECT COALESCE(NULLIF(started_at,''),created_at) FROM scans WHERE scans.id=observations.scan_id) WHERE seen_at='' OR seen_at IS NULL`)
	return nil
}

func (s *Store) addColumn(table, col, def string) error {
	rows, err := s.DB.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return err
	}
	exists := false
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		if n == col {
			exists = true
		}
	}
	rows.Close()
	if exists {
		return nil
	}
	_, err = s.DB.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + col + ` ` + def)
	return err
}

func (s *Store) Audit(user, action, entity string, detail any) {
	d := ""
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			d = string(b)
		}
	}
	_, _ = s.DB.Exec(`INSERT INTO audit(ts,username,action,entity,detail) VALUES(?,?,?,?,?)`, Now(), user, action, entity, d)
}

// ---- settings (zawsze szyfrowane) ----

func (s *Store) GetSetting(key string) string {
	var v string
	if err := s.DB.QueryRow(`SELECT value_enc FROM settings WHERE key=?`, key).Scan(&v); err != nil {
		return ""
	}
	return s.Box.MustOpen(v)
}

func (s *Store) SetSetting(key, val string) error {
	_, err := s.DB.Exec(`INSERT INTO settings(key,value_enc) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value_enc=excluded.value_enc`, key, s.Box.Seal(val))
	return err
}

func JSONList(v string) []string {
	var out []string
	_ = json.Unmarshal([]byte(v), &out)
	if out == nil {
		out = []string{}
	}
	return out
}

func ToJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TechBaseline: stan wyjściowy katalogu technologii. Technologie z pierwszej godziny pracy systemu (pierwszy inwentarz)
// są oznaczane jako znane; wszystko, co pojawiło się później, zostaje „nowe” i czeka na klasyfikację analityka.
func (s *Store) TechBaseline() {
	var first string
	if s.DB.QueryRow(`SELECT COALESCE(MIN(first_seen),'') FROM technologies WHERE first_seen!=''`).Scan(&first) != nil || first == "" {
		return
	}
	t, err := time.Parse(time.RFC3339, first)
	if err != nil {
		return
	}
	_, _ = s.DB.Exec(`UPDATE technologies SET status='reviewed', decision='znana', reviewed_by='stan wyjściowy', reviewed_at=?
WHERE status='new' AND first_seen <= ?`, Now(), t.Add(time.Hour).UTC().Format(time.RFC3339))
}
