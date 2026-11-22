package scan

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/asi-agh/asi/internal/ports"
	"github.com/asi-agh/asi/internal/store"
)

// Config: konfiguracja skanu (profil). Porty są zawsze podawane przez użytkownika.
type Config struct {
	ID              int64    `json:"id"`
	Name            string   `json:"name"`
	TargetTags      []string `json:"target_tags"`
	Ports           string   `json:"ports"`
	DiscoveryPorts  string   `json:"discovery_ports"`
	Rate            int      `json:"rate"`
	HTTPRPS         int      `json:"http_rps"`
	Workers         int      `json:"workers"`
	ChunkTargetSec  int      `json:"chunk_target_sec"`
	HostTimeoutSec  int      `json:"host_timeout_sec"`
	Retries         int      `json:"retries"`
	RetryUnstable   bool     `json:"retry_unstable"`
	HTTPProbe       bool     `json:"http_probe"`
	VersionIntens   int      `json:"version_intensity"`
	GoneAfter       int      `json:"gone_after"`
	Excludes        string   `json:"excludes"`
	SchedEnabled    bool     `json:"sched_enabled"`
	SchedEveryMin   int      `json:"sched_every_min"`
	WinStart        string   `json:"win_start"`
	WinEnd          string   `json:"win_end"`
	WinDays         string   `json:"win_days"`
	NextRun         string   `json:"next_run"`
	RetryEnabled    bool     `json:"retry_enabled"`   // doskanowanie nieosiągniętych końcówek poza głównym oknem
	RetryStart      string   `json:"retry_win_start"`
	RetryEnd        string   `json:"retry_win_end"`
	RetryBatch      int      `json:"retry_batch"`
	RetryEveryMin   int      `json:"retry_every_min"`
	RetryNext       string   `json:"retry_next"`
	RetryPauseSec   int      `json:"retry_pause_sec"` // przerwa między kolejnymi adresami doskanowania
	DojoAuto        bool     `json:"dojo_auto"`       // automatyczny eksport do DefectDojo po zakończeniu skanu
	DojoMinInterest int      `json:"dojo_min_interest"`
	AutoAddPorts    bool     `json:"auto_add_ports"` // dopisywanie wykrytych portów (tylko w ramach portów zatwierdzonych przez administratora)
	CreatedBy       string   `json:"created_by,omitempty"`
	CreatedAt       string   `json:"created_at,omitempty"`
	UpdatedAt       string   `json:"updated_at,omitempty"`
}

func (c *Config) Normalize() error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return fmt.Errorf("nazwa konfiguracji jest wymagana")
	}
	if strings.TrimSpace(c.Ports) == "" {
		return fmt.Errorf("podaj porty do skanowania (np. 22,80,443 albo 1-1024)")
	}
	sp, err := ports.Parse(c.Ports)
	if err != nil {
		return err
	}
	c.Ports = sp.String()
	if c.DiscoveryPorts != "" {
		dp, err := ports.Parse(c.DiscoveryPorts)
		if err != nil {
			return fmt.Errorf("porty discovery: %w", err)
		}
		c.DiscoveryPorts = dp.String()
	}
	c.Rate = clamp(c.Rate, 10, 100000, 1000)
	c.HTTPRPS = clamp(c.HTTPRPS, 1, 1000, 30)
	c.Workers = clamp(c.Workers, 1, 64, 4)
	c.ChunkTargetSec = clamp(c.ChunkTargetSec, 10, 3600, 60)
	c.HostTimeoutSec = clamp(c.HostTimeoutSec, 10, 3600, 120)
	c.Retries = clamp(c.Retries, 0, 5, 1)
	c.VersionIntens = clamp(c.VersionIntens, 0, 9, 5)
	c.GoneAfter = clamp(c.GoneAfter, 1, 50, 3)
	c.SchedEveryMin = clamp(c.SchedEveryMin, 5, 60*24*31, 1440)
	if c.WinStart == "" {
		c.WinStart = "00:00"
	}
	if c.WinEnd == "" {
		c.WinEnd = "23:59"
	}
	if _, err := time.Parse("15:04", c.WinStart); err != nil {
		return fmt.Errorf("niepoprawny początek okna (HH:MM)")
	}
	if _, err := time.Parse("15:04", c.WinEnd); err != nil {
		return fmt.Errorf("niepoprawny koniec okna (HH:MM)")
	}
	if c.WinDays == "" {
		c.WinDays = "1234567"
	}
	if c.TargetTags == nil {
		c.TargetTags = []string{}
	}
	if c.RetryStart == "" {
		c.RetryStart = "07:00"
	}
	if c.RetryEnd == "" {
		c.RetryEnd = "21:00"
	}
	if _, err := time.Parse("15:04", c.RetryStart); err != nil {
		return fmt.Errorf("niepoprawny początek okna doskanowania (HH:MM)")
	}
	if _, err := time.Parse("15:04", c.RetryEnd); err != nil {
		return fmt.Errorf("niepoprawny koniec okna doskanowania (HH:MM)")
	}
	c.RetryBatch = clamp(c.RetryBatch, 1, 256, 1)
	if c.RetryPauseSec <= 0 {
		c.RetryPauseSec = 15
	}
	c.RetryPauseSec = min(c.RetryPauseSec, 3600)
	c.DojoMinInterest = max(0, min(100, c.DojoMinInterest))
	c.RetryEveryMin = clamp(c.RetryEveryMin, 1, 1440, 10)
	return nil
}

// RetryWindow: okno doskanowania jako konfiguracja okna (te same dni tygodnia).
func (c *Config) RetryWindow() *Config {
	return &Config{WinStart: c.RetryStart, WinEnd: c.RetryEnd, WinDays: c.WinDays}
}

func clamp(v, lo, hi, def int) int {
	if v == 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

const cfgCols = `id,name,target_tags,ports,discovery_ports,rate,http_rps,workers,chunk_target_sec,host_timeout_sec,retries,
retry_unstable,http_probe,version_intensity,gone_after,excludes,sched_enabled,sched_every_min,win_start,win_end,win_days,next_run,
COALESCE(created_by,''),COALESCE(created_at,''),COALESCE(updated_at,''),retry_enabled,retry_win_start,retry_win_end,retry_batch,retry_every_min,retry_next,
retry_pause_sec,dojo_auto,dojo_min_interest,auto_add_ports`

func scanCfg(row interface{ Scan(...any) error }) (*Config, error) {
	c := &Config{}
	var tags string
	var ru, hp, se, re, da, aa int
	err := row.Scan(&c.ID, &c.Name, &tags, &c.Ports, &c.DiscoveryPorts, &c.Rate, &c.HTTPRPS, &c.Workers, &c.ChunkTargetSec,
		&c.HostTimeoutSec, &c.Retries, &ru, &hp, &c.VersionIntens, &c.GoneAfter, &c.Excludes, &se, &c.SchedEveryMin,
		&c.WinStart, &c.WinEnd, &c.WinDays, &c.NextRun, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
		&re, &c.RetryStart, &c.RetryEnd, &c.RetryBatch, &c.RetryEveryMin, &c.RetryNext, &c.RetryPauseSec, &da, &c.DojoMinInterest, &aa)
	c.DojoAuto, c.AutoAddPorts = da == 1, aa == 1
	c.TargetTags = store.JSONList(tags)
	c.RetryUnstable, c.HTTPProbe, c.SchedEnabled, c.RetryEnabled = ru == 1, hp == 1, se == 1, re == 1
	return c, err
}

func GetConfig(db *sql.DB, id int64) (*Config, error) {
	return scanCfg(db.QueryRow(`SELECT `+cfgCols+` FROM scan_configs WHERE id=?`, id))
}

func ListConfigs(db *sql.DB) ([]*Config, error) {
	rows, err := db.Query(`SELECT ` + cfgCols + ` FROM scan_configs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Config
	for rows.Next() {
		c, err := scanCfg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func SaveConfig(db *sql.DB, c *Config, user string) error {
	if err := c.Normalize(); err != nil {
		return err
	}
	now := store.Now()
	if c.SchedEnabled {
		// następny start: najbliższe okno, ale nie wcześniej niż ostatni przebieg + interwał
		from := time.Now()
		var last string
		if c.ID != 0 {
			_ = db.QueryRow(`SELECT COALESCE(MAX(created_at),'') FROM scans WHERE config_id=? AND source='scan'`, c.ID).Scan(&last)
		}
		if t, err := time.Parse(time.RFC3339, last); err == nil {
			if n := t.Add(time.Duration(c.SchedEveryMin) * time.Minute); n.After(from) {
				from = n
			}
		}
		c.NextRun = NextWindowStart(c, from).UTC().Format(time.RFC3339)
	} else {
		c.NextRun = ""
	}
	args := []any{c.Name, store.ToJSON(c.TargetTags), c.Ports, c.DiscoveryPorts, c.Rate, c.HTTPRPS, c.Workers, c.ChunkTargetSec,
		c.HostTimeoutSec, c.Retries, b2i(c.RetryUnstable), b2i(c.HTTPProbe), c.VersionIntens, c.GoneAfter, c.Excludes,
		b2i(c.SchedEnabled), c.SchedEveryMin, c.WinStart, c.WinEnd, c.WinDays, c.NextRun,
		b2i(c.RetryEnabled), c.RetryStart, c.RetryEnd, c.RetryBatch, c.RetryEveryMin, c.RetryPauseSec, b2i(c.DojoAuto), c.DojoMinInterest, b2i(c.AutoAddPorts)}
	if c.ID == 0 {
		// bez AUTOINCREMENT SQLite użyłby ponownie ID usuniętej reguły i nowa reguła przejęłaby jej historię skanów
		var next int64
		_ = db.QueryRow(`SELECT MAX(m)+1 FROM (SELECT COALESCE(MAX(id),0) m FROM scan_configs UNION ALL SELECT COALESCE(MAX(config_id),0) FROM scans)`).Scan(&next)
		res, err := db.Exec(`INSERT INTO scan_configs(id,name,target_tags,ports,discovery_ports,rate,http_rps,workers,chunk_target_sec,
host_timeout_sec,retries,retry_unstable,http_probe,version_intensity,gone_after,excludes,sched_enabled,sched_every_min,win_start,
win_end,win_days,next_run,retry_enabled,retry_win_start,retry_win_end,retry_batch,retry_every_min,retry_pause_sec,dojo_auto,dojo_min_interest,auto_add_ports,
created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			append(append([]any{max(next, 1)}, args...), user, now, now)...)
		if err != nil {
			return err
		}
		c.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := db.Exec(`UPDATE scan_configs SET name=?,target_tags=?,ports=?,discovery_ports=?,rate=?,http_rps=?,workers=?,chunk_target_sec=?,
host_timeout_sec=?,retries=?,retry_unstable=?,http_probe=?,version_intensity=?,gone_after=?,excludes=?,sched_enabled=?,sched_every_min=?,
win_start=?,win_end=?,win_days=?,next_run=?,retry_enabled=?,retry_win_start=?,retry_win_end=?,retry_batch=?,retry_every_min=?,
retry_pause_sec=?,dojo_auto=?,dojo_min_interest=?,auto_add_ports=?,updated_at=? WHERE id=?`, append(args, now, c.ID)...)
	return err
}

// ---- okna czasowe ----

func hm(s string) int {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0
	}
	return t.Hour()*60 + t.Minute()
}

func dayAllowed(c *Config, t time.Time) bool {
	wd := int(t.Weekday())
	if wd == 0 {
		wd = 7
	}
	return strings.ContainsRune(c.WinDays, rune('0'+wd))
}

// InWindow: czy t mieści się w oknie (obsługa okien przez północ, np. 22:00–06:00). Zwraca koniec okna.
func InWindow(c *Config, t time.Time) (bool, time.Time) {
	t = t.Local()
	s, e := hm(c.WinStart), hm(c.WinEnd)
	m := t.Hour()*60 + t.Minute()
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	if s <= e {
		if m >= s && m < e && dayAllowed(c, t) {
			return true, day.Add(time.Duration(e) * time.Minute)
		}
		if s == 0 && e == 23*60+59 && dayAllowed(c, t) {
			return true, day.Add(24 * time.Hour)
		}
		return false, time.Time{}
	}
	if m >= s && dayAllowed(c, t) { // wieczorna część okna
		return true, day.Add(24*time.Hour + time.Duration(e)*time.Minute)
	}
	if m < e && dayAllowed(c, t.Add(-24*time.Hour)) { // poranna część okna rozpoczętego wczoraj
		return true, day.Add(time.Duration(e) * time.Minute)
	}
	return false, time.Time{}
}

// NextWindowStart: najbliższa chwila >= t, w której okno jest otwarte.
func NextWindowStart(c *Config, t time.Time) time.Time {
	t = t.Local().Truncate(time.Minute)
	for i := 0; i < 8*24*60; i += 1 {
		x := t.Add(time.Duration(i) * time.Minute)
		if ok, _ := InWindow(c, x); ok {
			return x
		}
	}
	return t
}
