package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/asi-agh/asi/internal/diff"
	"github.com/asi-agh/asi/internal/ports"
	"github.com/asi-agh/asi/internal/scan"
	"github.com/asi-agh/asi/internal/secure"
	"github.com/asi-agh/asi/internal/store"
	"github.com/asi-agh/asi/internal/targets"
)

func hashPw(p string) string { return secure.HashPassword(p) }

// ---- cele ----

type targetOut struct {
	ID        int64    `json:"id"`
	Value     string   `json:"value"`
	Kind      string   `json:"kind"`
	Tags      []string `json:"tags"`
	Note      string   `json:"note"`
	Enabled   bool     `json:"enabled"`
	Source    string   `json:"source"`
	Addresses int      `json:"addresses"`
	CreatedBy string   `json:"created_by"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

func (s *Server) loadTargets() ([]targetOut, error) {
	rows, err := s.S.DB.Query(`SELECT id,value,kind,tags,note_enc,enabled,source,COALESCE(created_by,''),COALESCE(created_at,''),COALESCE(updated_at,'') FROM targets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []targetOut{}
	for rows.Next() {
		var t targetOut
		var tags, note string
		var en int
		_ = rows.Scan(&t.ID, &t.Value, &t.Kind, &tags, &note, &en, &t.Source, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
		t.Tags, t.Note, t.Enabled = store.JSONList(tags), s.S.Box.MustOpen(note), en == 1
		t.Addresses = targets.CountEstimate([]string{t.Value})
		out = append(out, t)
	}
	return out, nil
}

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request) {
	ts, err := s.loadTargets()
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	total := 0
	for _, t := range ts {
		if t.Enabled {
			total += t.Addresses
		}
	}
	writeJSON(w, 200, map[string]any{"targets": ts, "total_addresses": total})
}

// addTargets: wspólna ścieżka dla formularza ręcznego i importu plików (ta sama walidacja).
func (s *Server) addTargets(ins []targets.Input, extraTags []string, source, by string) map[string]any {
	added, dup := 0, 0
	errs := []string{}
	now := store.Now()
	pol := scan.LoadPolicy(s.S)
	// istniejące sieci: ostrzeżenie o nakładaniu się (adres liczony raz w skanie, ale lista celów staje się nieczytelna)
	var existing []netip.Prefix
	var existingVal []string
	if er, err := s.S.DB.Query(`SELECT value FROM targets WHERE kind IN ('ip','cidr')`); err == nil {
		for er.Next() {
			var v string
			_ = er.Scan(&v)
			if p, err := netip.ParsePrefix(v); err == nil {
				existing, existingVal = append(existing, p), append(existingVal, v)
			} else if a, err := netip.ParseAddr(v); err == nil {
				existing, existingVal = append(existing, netip.PrefixFrom(a, a.BitLen())), append(existingVal, v)
			}
		}
		er.Close()
	}
	warns := []string{}
	tx, err := s.S.DB.Begin()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	defer tx.Rollback()
	for _, in := range ins {
		norm, kind, err := targets.Classify(in.Value)
		if err == nil && !pol.AllowedTarget(norm, string(kind)) {
			err = fmt.Errorf("%s: poza sieciami dozwolonymi przez administratora (Polityka skanera: %s)", norm, strings.Join(pol.AllowCIDRs, ", "))
		}
		if err != nil {
			if len(errs) < 50 {
				errs = append(errs, err.Error())
			}
			continue
		}
		tags := append(append([]string{}, in.Tags...), extraTags...)
		res, err := tx.Exec(`INSERT OR IGNORE INTO targets(value,kind,tags,note_enc,source,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
			norm, string(kind), store.ToJSON(uniq(tags)), s.S.Box.Seal(in.Note), source, by, now, now)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if n, _ := res.RowsAffected(); n == 0 {
			dup++
		} else {
			added++
			np, perr := netip.ParsePrefix(norm)
			if perr != nil {
				if a, err := netip.ParseAddr(norm); err == nil {
					np, perr = netip.PrefixFrom(a, a.BitLen()), nil
				}
			}
			if perr == nil && len(warns) < 20 {
				for i, ep := range existing {
					if ep.Overlaps(np) && existingVal[i] != norm {
						warns = append(warns, fmt.Sprintf("%s pokrywa się z istniejącym celem %s (adresy wspólne skanowane są raz)", norm, existingVal[i]))
						break
					}
				}
			}
		}
	}
	_ = tx.Commit()
	return map[string]any{"added": added, "duplicates": dup, "errors": errs, "invalid": len(ins) - added - dup, "warnings": warns}
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[strings.ToLower(s)] {
			seen[strings.ToLower(s)] = true
			out = append(out, s)
		}
	}
	return out
}

func (s *Server) createTargets(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Text string   `json:"text"`
		Tags []string `json:"tags"`
		Note string   `json:"note"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	list, _ := targets.ParseText(in.Text)
	for i := range list {
		list[i].Note = in.Note
	}
	res := s.addTargets(list, in.Tags, "manual", user(r))
	s.S.Audit(user(r), "targets.create", "", res)
	writeJSON(w, 200, res)
}

func (s *Server) importTargets(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		fail(w, 400, "oczekiwano pliku (multipart/form-data)")
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		fail(w, 400, "brak pliku")
		return
	}
	defer f.Close()
	var list []targets.Input
	ext := strings.ToLower(filepath.Ext(hdr.Filename))
	data, _ := io.ReadAll(io.LimitReader(f, 64<<20))
	trim := strings.TrimSpace(string(data))
	switch {
	case ext == ".json" || strings.HasPrefix(trim, "[") || strings.HasPrefix(trim, "{"):
		list, err = targets.ParseJSON(strings.NewReader(trim))
	default:
		list, err = targets.ParseCSV(strings.NewReader(string(data)))
	}
	if err != nil {
		fail(w, 400, "błąd pliku: "+err.Error())
		return
	}
	tags := uniq(strings.Split(r.FormValue("tags"), ","))
	res := s.addTargets(list, tags, "import:"+hdr.Filename, user(r))
	res["rows"] = len(list)
	s.S.Audit(user(r), "targets.import", hdr.Filename, res)
	writeJSON(w, 200, res)
}

func (s *Server) updateTarget(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	var in struct {
		Value   *string  `json:"value"`
		Tags    []string `json:"tags"`
		Note    *string  `json:"note"`
		Enabled *bool    `json:"enabled"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	now := store.Now()
	if in.Value != nil {
		norm, kind, err := targets.Classify(*in.Value)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		if _, err := s.S.DB.Exec(`UPDATE targets SET value=?, kind=?, updated_at=? WHERE id=?`, norm, string(kind), now, id); err != nil {
			fail(w, 400, "taki cel już istnieje")
			return
		}
	}
	if in.Tags != nil {
		_, _ = s.S.DB.Exec(`UPDATE targets SET tags=?, updated_at=? WHERE id=?`, store.ToJSON(uniq(in.Tags)), now, id)
	}
	if in.Note != nil {
		_, _ = s.S.DB.Exec(`UPDATE targets SET note_enc=?, updated_at=? WHERE id=?`, s.S.Box.Seal(*in.Note), now, id)
	}
	if in.Enabled != nil {
		_, _ = s.S.DB.Exec(`UPDATE targets SET enabled=?, updated_at=? WHERE id=?`, boolInt(*in.Enabled), now, id)
	}
	s.S.Audit(user(r), "target.update", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	_, _ = s.S.DB.Exec(`DELETE FROM targets WHERE id=?`, id)
	s.S.Audit(user(r), "target.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) bulkDeleteTargets(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs []int64 `json:"ids"`
		All bool    `json:"all"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	n := 0
	if in.All {
		res, _ := s.S.DB.Exec(`DELETE FROM targets`)
		c, _ := res.RowsAffected()
		n = int(c)
	} else {
		for _, id := range in.IDs {
			res, _ := s.S.DB.Exec(`DELETE FROM targets WHERE id=?`, id)
			c, _ := res.RowsAffected()
			n += int(c)
		}
	}
	s.S.Audit(user(r), "targets.delete", "", map[string]int{"deleted": n})
	writeJSON(w, 200, map[string]int{"deleted": n})
}

// ---- porty ----

func (s *Server) portPresets(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	for k, v := range ports.Presets {
		sp, _ := ports.Parse(v)
		out[k] = map[string]any{"ports": v, "count": sp.Count()}
	}
	writeJSON(w, 200, out)
}

func (s *Server) validatePorts(w http.ResponseWriter, r *http.Request) {
	var in struct{ Ports string }
	_ = readJSON(r, &in)
	sp, err := ports.Parse(in.Ports)
	if err != nil {
		writeJSON(w, 200, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"valid": true, "normalized": sp.String(), "tcp": len(sp.TCP), "udp": len(sp.UDP), "discovery_only": sp.Empty()})
}

// ---- konfiguracje ----

func (s *Server) listConfigs(w http.ResponseWriter, r *http.Request) {
	cs, err := scan.ListConfigs(s.S.DB)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	if cs == nil {
		cs = []*scan.Config{}
	}
	writeJSON(w, 200, cs)
}

func (s *Server) saveConfig(w http.ResponseWriter, r *http.Request) {
	var c scan.Config
	if err := readJSON(r, &c); err != nil {
		fail(w, 400, "niepoprawne dane: "+err.Error())
		return
	}
	c.ID = idParam(r)
	if err := c.Normalize(); err != nil {
		fail(w, 400, err.Error())
		return
	}
	clamped := scan.LoadPolicy(s.S).Clamp(&c) // limity administratora: zapisujemy wartość obciętą
	if err := scan.SaveConfig(s.S.DB, &c, user(r)); err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.S.Audit(user(r), "config.save", c.Name, map[string]any{"ports": c.Ports, "rate": c.Rate, "workers": c.Workers})
	out := map[string]any{}
	b, _ := json.Marshal(c)
	_ = json.Unmarshal(b, &out)
	out["policy_clamped"] = clamped
	if clamped == nil {
		out["policy_clamped"] = []string{}
	}
	writeJSON(w, 200, out)
}

func (s *Server) deleteConfig(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	_, _ = s.S.DB.Exec(`DELETE FROM scan_configs WHERE id=?`, id)
	s.S.Audit(user(r), "config.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) runConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := scan.GetConfig(s.S.DB, idParam(r))
	if err != nil {
		fail(w, 404, "brak konfiguracji")
		return
	}
	var in struct {
		RespectWindow bool   `json:"respect_window"`
		Name          string `json:"name"`
		Tag           string `json:"tag"`
	}
	_ = readJSON(r, &in)
	if in.Tag == "" {
		in.Tag = in.Name
	}
	var deadline time.Time
	if in.RespectWindow {
		ok, end := scan.InWindow(cfg, time.Now())
		if !ok {
			fail(w, 400, "jesteśmy poza oknem czasowym tej konfiguracji")
			return
		}
		deadline = end
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	id, err := s.E.CreateScan(ctx, cfg, nil, user(r), in.Name)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if t := strings.TrimSpace(in.Tag); t != "" {
		_, _ = s.S.DB.Exec(`UPDATE scans SET tag=? WHERE id=?`, t, id) // nazwa tylko, gdy użytkownik ją nadał
	}
	if err := s.E.Start(id, deadline); err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.S.Audit(user(r), "scan.run", strconv.FormatInt(id, 10), map[string]any{"config": cfg.Name})
	writeJSON(w, 200, map[string]any{"scan_id": id})
}

// retryCandidates: końcówki czekające na doskanowanie (nie odpowiedziały w ostatnim skanie).
func (s *Server) retryCandidates(w http.ResponseWriter, r *http.Request) {
	ips, err := s.E.RetryCandidates(idParam(r), 100000)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	if ips == nil {
		ips = []string{}
	}
	done, total := s.E.RetryProgress(idParam(r))
	writeJSON(w, 200, map[string]any{"count": len(ips), "ips": ips[:min(len(ips), 200)], "checked_since_scan": done, "pool": total})
}

// retryNow: ręczne uruchomienie jednej paczki doskanowania.
func (s *Server) retryNow(w http.ResponseWriter, r *http.Request) {
	cfg, err := scan.GetConfig(s.S.DB, idParam(r))
	if err != nil {
		fail(w, 404, "brak konfiguracji")
		return
	}
	if s.E.ActiveForConfig(cfg.ID) {
		fail(w, 400, "trwa pełny skan tej konfiguracji")
		return
	}
	ips, err := s.E.RetryCandidates(cfg.ID, cfg.RetryBatch)
	if err != nil || len(ips) == 0 {
		fail(w, 400, "brak końcówek do doskanowania")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	res, err := s.E.RetryBatch(ctx, cfg, ips)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.S.Audit(user(r), "scan.retry", cfg.Name, res)
	writeJSON(w, 200, res)
}

// estimateConfig: szacunek czasu na podstawie historii tempa (IP/s) dla tej konfiguracji.
func (s *Server) estimateConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := scan.GetConfig(s.S.DB, idParam(r))
	if err != nil {
		fail(w, 404, "brak konfiguracji")
		return
	}
	writeJSON(w, 200, s.estimateFor(cfg))
}

// estimateDraft: szacowany czas dla reguły z formularza (także jeszcze niezapisanej).
func (s *Server) estimateDraft(w http.ResponseWriter, r *http.Request) {
	var cfg scan.Config
	if err := readJSON(r, &cfg); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	writeJSON(w, 200, s.estimateFor(&cfg))
}

// estimateFor: liczba adresów z celów reguły i tempo z historii skanów (tej reguły albo wszystkich).
func (s *Server) estimateFor(cfg *scan.Config) map[string]any {
	var values []string
	rows, _ := s.S.DB.Query(`SELECT value,tags FROM targets WHERE enabled=1`)
	for rows != nil && rows.Next() {
		var v, tags string
		_ = rows.Scan(&v, &tags)
		if len(cfg.TargetTags) == 0 || intersect(cfg.TargetTags, store.JSONList(tags)) {
			values = append(values, v)
		}
	}
	if rows != nil {
		rows.Close()
	}
	n := targets.CountEstimate(values)
	var ips, ms int64
	rate := 0.0
	basis := "historia skanów tej reguły"
	if cfg.ID > 0 {
		_ = s.S.DB.QueryRow(`SELECT COALESCE(SUM(j.ips),0),COALESCE(SUM(j.duration_ms),0) FROM scan_jobs j JOIN scans sc ON sc.id=j.scan_id WHERE sc.config_id=?`, cfg.ID).Scan(&ips, &ms)
	}
	if ips > 0 && ms > 0 {
		rate = float64(ips) / (float64(ms) / 1000) * float64(cfg.Workers)
	} else {
		_ = s.S.DB.QueryRow(`SELECT COALESCE(SUM(ips),0),COALESCE(SUM(duration_ms),0) FROM scan_jobs`).Scan(&ips, &ms)
		if ips > 0 && ms > 0 {
			rate = float64(ips) / (float64(ms) / 1000) * float64(cfg.Workers)
			basis = "historia wszystkich skanów"
		} else {
			rate = float64(cfg.Workers) * 4
			basis = "założenie wstępne (brak historii)"
		}
	}
	sec := float64(n) / max(rate, 0.1)
	return map[string]any{"addresses": n, "rate_ips": rate, "estimated_sec": int(sec), "basis": basis}
}

func intersect(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if strings.EqualFold(x, y) {
				return true
			}
		}
	}
	return false
}

// ---- skany ----

type scanOut struct {
	ID          int64          `json:"id"`
	ConfigID    int64          `json:"config_id"`
	Name        string         `json:"name"`
	Status      string         `json:"status"`
	Ports       string         `json:"ports"`
	Total       int            `json:"total_ips"`
	Done        int            `json:"done_ips"`
	Live        int            `json:"live_hosts"`
	Services    int            `json:"open_services"`
	CreatedAt   string         `json:"created_at"`
	StartedAt   string         `json:"started_at"`
	FinishedAt  string         `json:"finished_at"`
	ElapsedMs   int64          `json:"elapsed_ms"`
	Windows     int            `json:"windows"`
	TriggeredBy string         `json:"triggered_by"`
	Note        string         `json:"note"`
	Error       string         `json:"error"`
	Source      string         `json:"source"`
	Tag         string         `json:"tag"`  // nazwa nadana przez użytkownika (pusta = brak)
	Rule        string         `json:"rule"` // reguła (konfiguracja), z której wystartował skan
	RuleDeleted bool           `json:"rule_deleted"`
	Kind        string         `json:"kind"`  // harmonogram | doskanowanie | ręczny | import
	Label       string         `json:"label"` // do wyświetlania: tag albo „typ · reguła · data”
	Live2       scan.LiveStats `json:"live"`
}

const scanColsSQL = `id,COALESCE(config_id,0),name,status,ports,total_ips,done_ips,live_hosts,open_services,created_at,started_at,finished_at,elapsed_ms,windows,triggered_by,note_enc,error,source,
COALESCE(tag,''),COALESCE((SELECT c.name FROM scan_configs c WHERE c.id=scans.config_id),''),COALESCE(json_extract(config_snapshot,'$.name'),''),COALESCE(json_extract(config_snapshot,'$.win_start'),''),COALESCE(json_extract(config_snapshot,'$.win_end'),'')`

func (s *Server) scanRow(row interface{ Scan(...any) error }) (*scanOut, error) {
	o := &scanOut{}
	var note, ws, we, snapName string
	err := row.Scan(&o.ID, &o.ConfigID, &o.Name, &o.Status, &o.Ports, &o.Total, &o.Done, &o.Live, &o.Services, &o.CreatedAt, &o.StartedAt,
		&o.FinishedAt, &o.ElapsedMs, &o.Windows, &o.TriggeredBy, &note, &o.Error, &o.Source, &o.Tag, &o.Rule, &snapName, &ws, &we)
	if o.Rule == "" && o.ConfigID > 0 { // reguła usunięta: nazwa z migawki konfiguracji zapisanej przy skanie
		o.RuleDeleted = true
		o.Rule = snapName
		if o.Rule == "" {
			o.Rule = fmt.Sprintf("reguła #%d", o.ConfigID)
		}
		o.Rule += " (usunięta)"
	}
	o.Note = s.S.Box.MustOpen(note)
	o.Kind = scanKind(o.Source, o.TriggeredBy, ws, we)
	o.Label = scanLabel(o)
	o.Live2 = s.E.Live(o.ID)
	// elapsed_ms w bazie jest aktualizowany co 10 s przez silnik (także w trakcie okna)
	return o, err
}

// scanKind: typ skanu wynikający wyłącznie z ustawień reguły (bez zaszytych pór dnia):
// harmonogram (okno i częstotliwość ustawione w regule), doskanowanie (doskaner reguły), ręczny, import.
func scanKind(source, trig, ws, we string) string {
	switch {
	case source == "retry":
		return "doskanowanie"
	case source == "import":
		return "import"
	case trig == "harmonogram":
		return "harmonogram"
	}
	return "ręczny"
}

// scanLabel: tag użytkownika albo automatycznie „reguła · data” (typ pokazujemy osobno).
func scanLabel(o *scanOut) string {
	if o.Tag != "" {
		return o.Tag
	}
	when := o.StartedAt
	if when == "" {
		when = o.CreatedAt
	}
	if t, err := time.Parse(time.RFC3339, when); err == nil {
		if o.Kind == "doskanowanie" {
			when = t.Local().Format("02.01.2006")
		} else {
			when = t.Local().Format("02.01.2006 15:04")
		}
	}
	if o.Rule == "" {
		return map[string]string{"import": "Import"}[o.Kind] + " · " + when
	}
	return o.Rule + " · " + when
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	rows, err := s.S.DB.Query(`SELECT `+scanColsSQL+` FROM scans ORDER BY id DESC LIMIT ?`, qint(r, "limit", 200))
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []*scanOut{}
	for rows.Next() {
		o, err := s.scanRow(rows)
		if err == nil {
			out = append(out, o)
		}
	}
	writeJSON(w, 200, out)
}

// scanHosts: końcówki z danego skanu (odpowiedziały / nie odpowiedziały) z ich bieżącym stanem.
func (s *Server) scanHosts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.S.DB.Query(`SELECT sh.ip, sh.alive, sh.hostname, sh.reason, sh.retried, COALESCE(h.state,''), COALESCE(h.last_seen,''), COALESCE(h.history,''), COALESCE(h.miss_streak,0)
FROM scan_hosts sh LEFT JOIN hosts h ON h.ip=sh.ip WHERE sh.scan_id=? ORDER BY sh.alive, sh.ip`, idParam(r))
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var ip, hn, reason, state, last, hist string
		var alive, retried, miss int
		_ = rows.Scan(&ip, &alive, &hn, &reason, &retried, &state, &last, &hist, &miss)
		out = append(out, map[string]any{"ip": ip, "alive": alive == 1, "hostname": hn, "reason": reason, "retried": retried == 1,
			"state": state, "last_seen": last, "history": hist, "miss_streak": miss})
	}
	writeJSON(w, 200, out)
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	o, err := s.scanRow(s.S.DB.QueryRow(`SELECT `+scanColsSQL+` FROM scans WHERE id=?`, id))
	if err != nil {
		fail(w, 404, "brak skanu")
		return
	}
	jobs := []map[string]any{}
	rows, _ := s.S.DB.Query(`SELECT ips,live,services,started_at,duration_ms,worker FROM scan_jobs WHERE scan_id=? ORDER BY id`, id)
	for rows != nil && rows.Next() {
		var ips, live, svc, worker int
		var st string
		var ms int64
		_ = rows.Scan(&ips, &live, &svc, &st, &ms, &worker)
		jobs = append(jobs, map[string]any{"ips": ips, "live": live, "services": svc, "started_at": st, "duration_ms": ms, "worker": worker})
	}
	if rows != nil {
		rows.Close()
	}
	blocks := map[string]int{}
	brows, _ := s.S.DB.Query(`SELECT status,COUNT(*) FROM scan_blocks WHERE scan_id=? GROUP BY status`, id)
	for brows != nil && brows.Next() {
		var st string
		var n int
		_ = brows.Scan(&st, &n)
		blocks[st] = n
	}
	if brows != nil {
		brows.Close()
	}
	var snap string
	_ = s.S.DB.QueryRow(`SELECT config_snapshot FROM scans WHERE id=?`, id).Scan(&snap)
	var cfg any
	_ = json.Unmarshal([]byte(snap), &cfg)
	eta := 0
	if o.Live2.Running && o.Live2.Rate > 0 {
		eta = int(float64(o.Total-o.Done) / (o.Live2.Rate * float64(max(1, o.Live2.InFlight))))
	}
	writeJSON(w, 200, map[string]any{"scan": o, "jobs": jobs, "blocks": blocks, "config": cfg, "eta_sec": eta})
}

func (s *Server) updateScan(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	var in struct {
		Name *string `json:"name"`
		Tag  *string `json:"tag"`
		Note *string `json:"note"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	if in.Tag == nil {
		in.Tag = in.Name // zgodność wstecz: „name” z API = tag
	}
	if in.Tag != nil {
		_, _ = s.S.DB.Exec(`UPDATE scans SET tag=? WHERE id=?`, strings.TrimSpace(*in.Tag), id)
	}
	if in.Note != nil {
		_, _ = s.S.DB.Exec(`UPDATE scans SET note_enc=? WHERE id=?`, s.S.Box.Seal(*in.Note), id)
	}
	s.S.Audit(user(r), "scan.update", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) deleteScan(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	if s.E.IsActive(id) {
		fail(w, 400, "zatrzymaj skan przed usunięciem")
		return
	}
	_, _ = s.S.DB.Exec(`DELETE FROM scans WHERE id=?`, id)
	s.S.Audit(user(r), "scan.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) cancelScan(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	if !s.E.Cancel(id) {
		_, _ = s.S.DB.Exec(`UPDATE scans SET status='cancelled' WHERE id=? AND status IN ('paused','queued')`, id)
	}
	s.S.Audit(user(r), "scan.cancel", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) resumeScan(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	var st string
	_ = s.S.DB.QueryRow(`SELECT status FROM scans WHERE id=?`, id).Scan(&st)
	if st != "paused" && st != "cancelled" && st != "failed" {
		fail(w, 400, "można wznowić tylko skan wstrzymany, anulowany lub nieudany")
		return
	}
	if err := s.E.Start(id, time.Time{}); err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.S.Audit(user(r), "scan.resume", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// reevaluate: ponowne zastosowanie aktualnych sygnatur do zapisanych wyników (bez ruchu sieciowego).
func (s *Server) reevaluate(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	obs, err := scan.ListObs(s.S, `WHERE scan_id=?`, true, id)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	for _, o := range obs {
		if o.Data.HTTP != nil {
			o.Data.HTTP.Body = o.Data.HTTP.BodySnippet
		}
		o.Data.Detections = s.Sigs.Evaluate(scan.SigInput(o))
		o.Finalize()
		scan.Score(o)
		blob, _ := json.Marshal(o.Data)
		_, _ = s.S.DB.Exec(`UPDATE observations SET techs=?, flags=?, interest=?, fingerprint=?, data_enc=? WHERE id=?`,
			store.ToJSON(o.Techs), store.ToJSON(o.Flags), o.Interest, o.Fingerprint, s.S.Box.Seal(string(blob)), o.ID)
	}
	s.S.Audit(user(r), "scan.reevaluate", strconv.FormatInt(id, 10), map[string]int{"observations": len(obs)})
	writeJSON(w, 200, map[string]int{"updated": len(obs)})
}

// ---- wyniki ----

type obsView struct {
	*scan.Observation
	Title      string      `json:"title"`
	Server     string      `json:"server"`
	RulesTotal int         `json:"rules_total"`
	Hostname   string      `json:"hostname"`
	Annotation *annotation `json:"annotation,omitempty"`
	SvcState   string      `json:"service_state,omitempty"`
	FirstSeen  string      `json:"first_seen,omitempty"`
	LastSeen   string      `json:"last_seen,omitempty"`
}

func view(o *scan.Observation, full bool) *obsView {
	v := &obsView{Observation: o, Hostname: o.Data.Hostname, RulesTotal: scan.ActiveRules().Enabled()}
	if h := o.Data.HTTP; h != nil {
		v.Title = h.Title
		if sv := h.Headers["server"]; len(sv) > 0 {
			v.Server = sv[0]
		}
	}
	if !full {
		cp := *o
		cp.Data = scan.ObsData{Hostname: o.Data.Hostname}
		v.Observation = &cp
	}
	return v
}

func matchObs(v *obsView, q, flag, tech string, minInterest int) bool {
	if v.Interest < minInterest {
		return false
	}
	if flag != "" {
		ok := false
		for _, f := range v.Flags {
			if f == flag {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if tech != "" {
		ok := false
		for _, t := range v.Techs {
			if strings.EqualFold(t.ID, tech) || strings.EqualFold(t.Category, tech) || strings.Contains(strings.ToLower(t.Name), strings.ToLower(tech)) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if q == "" {
		return true
	}
	q = strings.ToLower(q)
	hay := strings.ToLower(strings.Join([]string{v.IP, strconv.Itoa(v.Port), v.Service, v.Product, v.Version, v.Title, v.Server, v.Hostname}, " "))
	for _, t := range v.Techs {
		hay += " " + strings.ToLower(t.Name)
	}
	if v.Annotation != nil {
		hay += " " + strings.ToLower(strings.Join(v.Annotation.Tags, " ")+" "+v.Annotation.Note+" "+v.Annotation.Owner)
	}
	return strings.Contains(hay, q)
}

func (s *Server) scanObservations(w http.ResponseWriter, r *http.Request) {
	obs, err := scan.ListObs(s.S, `WHERE scan_id=? ORDER BY interest DESC, ip, port`, true, idParam(r))
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	ann := s.annotations()
	out := []*obsView{}
	q := r.URL.Query()
	for _, o := range obs {
		v := view(o, false)
		v.Annotation = ann[svcKey(o.IP, o.Port, o.Proto)]
		if matchObs(v, q.Get("q"), q.Get("flag"), q.Get("tech"), qint(r, "min_interest", 0)) {
			out = append(out, v)
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) getObservation(w http.ResponseWriter, r *http.Request) {
	o, err := scan.GetObs(s.S, idParam(r))
	if err != nil {
		fail(w, 404, "brak obserwacji")
		return
	}
	v := view(o, true)
	ann := s.annotations()
	v.Annotation = ann[svcKey(o.IP, o.Port, o.Proto)]
	// historia tej usługi w kolejnych skanach
	hist := []map[string]any{}
	rows, _ := s.S.DB.Query(`SELECT o.id,o.scan_id,s.name,s.started_at,o.product,o.version,o.http_status,o.fingerprint FROM observations o JOIN scans s ON s.id=o.scan_id
WHERE o.ip=? AND o.port=? AND o.proto=? ORDER BY o.scan_id DESC LIMIT 30`, o.IP, o.Port, o.Proto)
	for rows != nil && rows.Next() {
		var id, sid int64
		var name, st, prod, ver, fp string
		var code int
		_ = rows.Scan(&id, &sid, &name, &st, &prod, &ver, &code, &fp)
		hist = append(hist, map[string]any{"obs_id": id, "scan_id": sid, "scan": name, "started_at": st, "product": prod, "version": ver, "http_status": code, "fingerprint": fp})
	}
	if rows != nil {
		rows.Close()
	}
	writeJSON(w, 200, map[string]any{"observation": v, "history": hist})
}

// updateObservation: edycja wyniku istniejącego skanu (oznaczana jako edytowana, z audytem).
func (s *Server) updateObservation(w http.ResponseWriter, r *http.Request) {
	o, err := scan.GetObs(s.S, idParam(r))
	if err != nil {
		fail(w, 404, "brak obserwacji")
		return
	}
	var in struct {
		Service  *string     `json:"service"`
		Product  *string     `json:"product"`
		Version  *string     `json:"version"`
		Note     *string     `json:"note"`
		Interest *int        `json:"interest"`
		Techs    []scan.Tech `json:"techs"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	before := map[string]any{"service": o.Service, "product": o.Product, "version": o.Version, "interest": o.Interest}
	techsBefore := scan.TechIDs(o.Techs)
	var snap *scan.Observation
	if !o.Edited {
		cp := *o
		snap = &cp
	}
	if in.Service != nil {
		o.Service = *in.Service
	}
	if in.Product != nil {
		o.Product, o.Data.Banner.Product = *in.Product, *in.Product
	}
	if in.Version != nil {
		o.Version, o.Data.Banner.Version = *in.Version, *in.Version
	}
	if in.Note != nil {
		o.Data.Note = *in.Note
	}
	if in.Techs != nil {
		o.Techs = in.Techs
		o.Data.Detections = nil
		for _, t := range in.Techs {
			o.Data.Detections = append(o.Data.Detections, sigDetection(t))
		}
	}
	if in.Interest != nil {
		o.Interest = max(0, min(100, *in.Interest))
	}
	blob, _ := json.Marshal(o.Data)
	_, err = s.S.DB.Exec(`UPDATE observations SET service=?, product=?, version=?, techs=?, interest=?, data_enc=?, edited=1, edited_by=? WHERE id=?`,
		o.Service, o.Product, o.Version, store.ToJSON(o.Techs), o.Interest, s.S.Box.Seal(string(blob)), user(r), o.ID)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	// zapamiętaj poprawkę na poziomie usługi, żeby nakładała się na kolejne skany
	if in.Techs != nil {
		_ = scan.TrackTechs(s.S.DB, o.ScanID, o) // technologia dopisana ręcznie trafia do katalogu i kolejki „do zaklasyfikowania”
	}
	// tylko pola faktycznie zmienione przez analityka; wcześniejsza poprawka tej usługi jest uzupełniana, nie zastępowana
	ent := scan.SvcEntity(o.IP, o.Port, o.Proto)
	ovs, _ := scan.LoadOverrides(s.S.DB)
	ov := ovs[ent]
	ov.By = user(r)
	if !ov.HasBase {
		ov.BaseService, _ = before["service"].(string)
		ov.BaseProduct, _ = before["product"].(string)
		ov.BaseVersion, _ = before["version"].(string)
		ov.HasBase = true
	}
	// powrót do wartości wykrytej przez skaner kasuje poprawkę tego pola (inaczej kolejny skan pokazałby fałszywą zmianę)
	if in.Service != nil {
		ov.Service = map[bool]string{true: "", false: o.Service}[*in.Service == ov.BaseService]
	}
	if in.Product != nil {
		ov.Product = map[bool]string{true: "", false: o.Product}[*in.Product == ov.BaseProduct]
	}
	if in.Version != nil {
		ov.Version = map[bool]string{true: "", false: o.Version}[*in.Version == ov.BaseVersion]
	}
	if in.Techs != nil && ov.BaseTechs == nil {
		ov.BaseTechs = techsBefore
	}
	if snap != nil && (ov.Snap == nil || ov.Snap.ID != o.ID) {
		ov.Snap = snap
	}
	if in.Note != nil {
		ov.Note = o.Data.Note
	}
	if in.Interest != nil {
		v := o.Interest
		ov.Interest = &v
	}
	if in.Techs != nil {
		ov.Techs = o.Techs
	}
	_, _ = s.S.DB.Exec(`INSERT INTO annotations(entity,tags,note_enc,owner,criticality,false_positive,tech_override,updated_by,updated_at)
VALUES(?,'[]',?,'',0,0,?,?,?) ON CONFLICT(entity) DO UPDATE SET tech_override=excluded.tech_override, updated_by=excluded.updated_by, updated_at=excluded.updated_at`,
		ent, s.S.Box.Seal(""), s.S.Box.Seal(store.ToJSON(ov)), user(r), store.Now())
	s.S.Audit(user(r), "observation.update", strconv.FormatInt(o.ID, 10), map[string]any{"before": before})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// clearOverride: cofa trwałą poprawkę analityka; kolejny skan zapisze znów wartości z nmapa i sygnatur.
func (s *Server) clearOverride(w http.ResponseWriter, r *http.Request) {
	o, err := scan.GetObs(s.S, idParam(r))
	if err != nil {
		fail(w, 404, "brak obserwacji")
		return
	}
	ent := scan.SvcEntity(o.IP, o.Port, o.Proto)
	ovs, _ := scan.LoadOverrides(s.S.DB)
	restored := false
	if ov, ok := ovs[ent]; ok && ov.Snap != nil && ov.Snap.ID == o.ID {
		// rekord wraca 1:1 do stanu zapisanego przez skaner (wykrycia z dowodami, wersje, fingerprint, klasa)
		p := ov.Snap
		blob, _ := json.Marshal(p.Data)
		_, _ = s.S.DB.Exec(`UPDATE observations SET service=?, product=?, version=?, techs=?, flags=?, interest=?, rules=?, fingerprint=?, data_enc=? WHERE id=?`,
			p.Service, p.Product, p.Version, store.ToJSON(p.Techs), store.ToJSON(p.Flags), p.Interest, store.ToJSON(p.Rules), p.Fingerprint, s.S.Box.Seal(string(blob)), o.ID)
		restored = true
	}
	_, _ = s.S.DB.Exec(`UPDATE annotations SET tech_override='', updated_by=?, updated_at=? WHERE entity=?`, user(r), store.Now(), ent)
	// pusty wiersz adnotacji (bez tagów, notatki, właściciela i fałszywego alarmu) nie jest potrzebny
	var noteEnc string
	if s.S.DB.QueryRow(`SELECT note_enc FROM annotations WHERE entity=? AND tech_override='' AND tags='[]' AND owner='' AND criticality=0 AND false_positive=0`, ent).Scan(&noteEnc) == nil &&
		s.S.Box.MustOpen(noteEnc) == "" {
		_, _ = s.S.DB.Exec(`DELETE FROM annotations WHERE entity=?`, ent)
	}
	_, _ = s.S.DB.Exec(`UPDATE observations SET edited=0, edited_by='' WHERE id=?`, o.ID)
	// technologie dopisane ręcznie, których nie ma już w żadnym rekordzie, znikają z katalogu i kolejki klasyfikacji
	_, _ = s.S.DB.Exec(`DELETE FROM technologies WHERE id LIKE 'analityk-%' AND NOT EXISTS (SELECT 1 FROM observations WHERE techs LIKE '%"' || technologies.id || '"%')`)
	s.S.Audit(user(r), "observation.override_clear", ent, map[string]bool{"restored": restored})
	writeJSON(w, 200, map[string]bool{"ok": true, "restored": restored})
}

func (s *Server) deleteObservation(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	_, _ = s.S.DB.Exec(`DELETE FROM observations WHERE id=?`, id)
	s.S.Audit(user(r), "observation.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---- adnotacje (dane od ludzi, nigdy nie nadpisywane przez skan) ----

type annotation struct {
	Entity        string   `json:"entity"`
	Tags          []string `json:"tags"`
	Note          string   `json:"note"`
	Owner         string   `json:"owner"`
	Criticality   int      `json:"criticality"`
	FalsePositive bool     `json:"false_positive"`
	TechOverride  string   `json:"-"` // poprawka z migawką skanera: tylko po stronie serwera
	UpdatedBy     string   `json:"updated_by"`
	UpdatedAt     string   `json:"updated_at"`
}

func svcKey(ip string, port int, proto string) string {
	return fmt.Sprintf("svc:%s:%d/%s", ip, port, proto)
}

func (s *Server) annotations() map[string]*annotation {
	out := map[string]*annotation{}
	rows, err := s.S.DB.Query(`SELECT entity,tags,note_enc,owner,criticality,false_positive,tech_override,updated_by,updated_at FROM annotations`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		a := &annotation{}
		var tags, note string
		var fp int
		_ = rows.Scan(&a.Entity, &tags, &note, &a.Owner, &a.Criticality, &fp, &a.TechOverride, &a.UpdatedBy, &a.UpdatedAt)
		a.Tags, a.Note, a.FalsePositive = store.JSONList(tags), s.S.Box.MustOpen(note), fp == 1
		if a.TechOverride != "" && !strings.HasPrefix(a.TechOverride, "{") {
			a.TechOverride = s.S.Box.MustOpen(a.TechOverride)
		}
		out[a.Entity] = a
	}
	return out
}

func (s *Server) saveAnnotation(w http.ResponseWriter, r *http.Request) {
	var a annotation
	if err := readJSON(r, &a); err != nil || !(strings.HasPrefix(a.Entity, "svc:") || strings.HasPrefix(a.Entity, "host:")) {
		fail(w, 400, "podaj entity (host:IP albo svc:IP:PORT/PROTO)")
		return
	}
	_, err := s.S.DB.Exec(`INSERT INTO annotations(entity,tags,note_enc,owner,criticality,false_positive,tech_override,updated_by,updated_at)
VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(entity) DO UPDATE SET tags=excluded.tags, note_enc=excluded.note_enc, owner=excluded.owner,
criticality=excluded.criticality, false_positive=excluded.false_positive,
tech_override=CASE WHEN excluded.tech_override='' THEN annotations.tech_override ELSE excluded.tech_override END,
updated_by=excluded.updated_by, updated_at=excluded.updated_at`, a.Entity, store.ToJSON(uniq(a.Tags)), s.S.Box.Seal(a.Note), a.Owner,
		max(0, min(5, a.Criticality)), boolInt(a.FalsePositive), "", user(r), store.Now()) // tech_override ustawia tylko „Edytuj wynik”
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	s.S.Audit(user(r), "annotation.save", a.Entity, map[string]any{"tags": a.Tags, "criticality": a.Criticality, "fp": a.FalsePositive})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---- hosty i usługi (bieżący stan inwentarza) ----

type hostOut struct {
	IP          string      `json:"ip"`
	Hostname    string      `json:"hostname"`
	State       string      `json:"state"`
	FirstSeen   string      `json:"first_seen"`
	LastSeen    string      `json:"last_seen"`
	SeenCount   int         `json:"seen_count"`
	ScanCount   int         `json:"scan_count"`
	MissStreak  int         `json:"miss_streak"`
	LastChecked string      `json:"last_checked"`
	StateSince  string      `json:"state_changed"`
	History     string      `json:"history"`
	HoursSeen   []int       `json:"hours_seen"`
	HoursScan   []int       `json:"hours_scanned"`
	DayPattern  string      `json:"day_pattern,omitempty"`
	NightSeen   int         `json:"night_seen"`
	NightScan   int         `json:"night_scanned"`
	DaySeen     int         `json:"day_seen"`
	DayScan     int         `json:"day_scanned"`
	Services    int         `json:"services"`
	MaxInterest int         `json:"max_interest"`
	Annotation  *annotation `json:"annotation,omitempty"`
}

// Widoki hostów:
//
//	active   = widziany w skanie w ciągu ostatnich 24 h (i nie jest niestabilny),
//	unstable = widziany w ciągu 24 h, ale w skanach nocnych (22–06) nie odpowiada: pojawia się tylko w dzień,
//	down     = niewidziany dłużej niż 48 h (albo nigdy).
func hostView(h *hostOut, now time.Time) string {
	t, err := time.Parse(time.RFC3339, h.LastSeen)
	if h.LastSeen == "" || err != nil || now.Sub(t) > 48*time.Hour {
		return "down"
	}
	if now.Sub(t) <= 24*time.Hour {
		if nightOff(h) {
			return "unstable"
		}
		return "active"
	}
	return "" // widziany 24–48 h temu: w żadnym widoku (przejściowo)
}

func filterView(hs []*hostOut, v string) []*hostOut {
	now, out := time.Now(), []*hostOut{}
	for _, h := range hs {
		if hostView(h, now) == v {
			out = append(out, h)
		}
	}
	return out
}

// hostViewCounts: liczności widoków (dla przycisków w Hostach i kafla na dashboardzie).
func (s *Server) hostViewCounts() map[string]int {
	out := map[string]int{"active": 0, "unstable": 0, "down": 0}
	hs, err := s.hostRows("")
	if err != nil {
		return out
	}
	now := time.Now()
	for _, h := range hs {
		if v := hostView(h, now); v != "" {
			out[v]++
		}
	}
	return out
}

// serviceViews: liczba usług w widokach hosta (te same definicje co w zakładce Hosty).
func (s *Server) serviceViews(w http.ResponseWriter, r *http.Request) {
	out := map[string]int{"active": 0, "unstable": 0, "down": 0}
	view := map[string]string{}
	if hs, err := s.hostRows(""); err == nil {
		now := time.Now()
		for _, h := range hs {
			view[h.IP] = hostView(h, now)
		}
	}
	// te same zapytania co lista usług: aktywne/niestabilne bez usług „gone”, niedostępne z ostatniej obserwacji
	live, err := s.currentServices("WHERE sv.state!='gone'")
	all, err2 := s.currentServices("WHERE 1=1")
	if err == nil && err2 == nil {
		count := func(list []*obsView, want func(string) bool) {
			for _, v := range list {
				hv := view[v.IP]
				if hv == "" || !want(hv) {
					continue
				}
				if r.URL.Query().Get("hide_fp") == "1" && v.Annotation != nil && v.Annotation.FalsePositive {
					continue // tak samo jak lista z włączonym „ukryj fałszywe alarmy”
				}
				out[hv]++
			}
		}
		count(live, func(hv string) bool { return hv != "down" })
		count(all, func(hv string) bool { return hv == "down" })
	}
	writeJSON(w, 200, out)
}

func (s *Server) hostViews(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.hostViewCounts())
}

// dayNight: sumy pomiarów i odpowiedzi w skanach nocnych (22:00–06:00) i dziennych (06:00–22:00), czas lokalny.
func dayNight(seen, scanned []int) (ns, nsc, ds, dsc int) {
	if len(seen) != 24 || len(scanned) != 24 {
		return
	}
	for h := 0; h < 24; h++ {
		if h >= 22 || h < 6 {
			ns, nsc = ns+seen[h], nsc+scanned[h]
		} else {
			ds, dsc = ds+seen[h], dsc+scanned[h]
		}
	}
	return
}

// nightOff: końcówka niestabilna wg pory dnia: w skanach nocnych (prawie) nie odpowiada, w dziennych odpowiada.
func nightOff(h *hostOut) bool {
	return h.NightScan > 0 && h.DaySeen > 0 && float64(h.NightSeen) <= 0.25*float64(h.NightScan)
}

// dayPattern: wykrywanie zależności od pory dnia (host widoczny tylko w części godzin).
func dayPattern(seen, scanned []int) string {
	if len(seen) != 24 || len(scanned) != 24 {
		return ""
	}
	var on, off []int
	for h := 0; h < 24; h++ {
		if scanned[h] < 1 {
			continue
		}
		ratio := float64(seen[h]) / float64(scanned[h])
		if ratio >= 0.75 {
			on = append(on, h)
		} else if ratio <= 0.25 {
			off = append(off, h)
		}
	}
	if len(on) == 0 || len(off) == 0 {
		return ""
	}
	hs := func(l []int) string {
		var p []string
		for _, h := range l {
			p = append(p, fmt.Sprintf("%02d", h))
		}
		return strings.Join(p, ",")
	}
	return "odpowiada w godzinach: " + hs(on) + "; brak odpowiedzi: " + hs(off)
}

func (s *Server) hostRows(where string, args ...any) ([]*hostOut, error) {
	rows, err := s.S.DB.Query(`SELECT h.ip,h.hostname,h.state,h.first_seen,h.last_seen,h.seen_count,h.scan_count,h.miss_streak,COALESCE(h.last_checked,''),COALESCE(h.state_changed,''),h.history,h.hours_seen,h.hours_scanned,
(SELECT COUNT(*) FROM services sv WHERE sv.ip=h.ip AND sv.state!='gone'),
(SELECT COALESCE(MAX(o.interest),0) FROM services sv JOIN observations o ON o.id=sv.last_obs_id WHERE sv.ip=h.ip AND sv.state!='gone')
FROM hosts h `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ann := s.annotations()
	out := []*hostOut{}
	for rows.Next() {
		h := &hostOut{}
		var hs, hsc string
		_ = rows.Scan(&h.IP, &h.Hostname, &h.State, &h.FirstSeen, &h.LastSeen, &h.SeenCount, &h.ScanCount, &h.MissStreak, &h.LastChecked, &h.StateSince, &h.History, &hs, &hsc, &h.Services, &h.MaxInterest)
		_ = json.Unmarshal([]byte(hs), &h.HoursSeen)
		_ = json.Unmarshal([]byte(hsc), &h.HoursScan)
		h.DayPattern = dayPattern(h.HoursSeen, h.HoursScan)
		h.NightSeen, h.NightScan, h.DaySeen, h.DayScan = dayNight(h.HoursSeen, h.HoursScan)
		h.Annotation = ann["host:"+h.IP]
		out = append(out, h)
	}
	return out, nil
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	where, args := "", []any{}
	if st := r.URL.Query().Get("state"); st != "" {
		where, args = "WHERE h.state=?", append(args, st)
	} else if sts := r.URL.Query().Get("states"); sts != "" {
		where, args = "WHERE h.state IN (SELECT value FROM json_each(?))", append(args, store.ToJSON(strings.Split(sts, ",")))
	}
	if hrs := qint(r, "unseen_hours", 0); hrs > 0 {
		// końcówki niewidziane przez skaner od co najmniej N godzin (albo nigdy)
		cut := time.Now().Add(-time.Duration(hrs) * time.Hour).UTC().Format(time.RFC3339)
		cond := "(COALESCE(h.last_seen,'')='' OR h.last_seen < ?)"
		if where == "" {
			where = "WHERE " + cond
		} else {
			where += " AND " + cond
		}
		args = append(args, cut)
	}
	hs, err := s.hostRows(where+" ORDER BY h.ip", args...)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	if v := r.URL.Query().Get("view"); v != "" {
		hs = filterView(hs, v)
	}
	q := strings.ToLower(r.URL.Query().Get("q"))
	night := r.URL.Query().Get("night_off") == "1"
	out := hs[:0]
	for _, h := range hs {
		if night && !nightOff(h) {
			continue
		}
		if q == "" || strings.Contains(strings.ToLower(h.IP+" "+h.Hostname), q) || (h.Annotation != nil && strings.Contains(strings.ToLower(strings.Join(h.Annotation.Tags, " ")+" "+h.Annotation.Note), q)) {
			out = append(out, h)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return ipLess(out[i].IP, out[j].IP) })
	writeJSON(w, 200, out)
}

func ipLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if len(pa) != 4 || len(pb) != 4 {
		return a < b
	}
	for i := 0; i < 4; i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return false
}

func (s *Server) currentServices(where string, args ...any) ([]*obsView, error) {
	// jedno złączenie zamiast zapytania na każdą usługę
	cols := scan.ObsColsPrefixed("o")
	rows, err := s.S.DB.Query(`SELECT sv.state,sv.first_seen,sv.last_seen,`+cols+` FROM services sv JOIN observations o ON o.id=sv.last_obs_id `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ann := s.annotations()
	out := []*obsView{}
	for rows.Next() {
		var state, first, last string
		o, err := scan.ScanObsPrefixed(s.S, rows, true, &state, &first, &last)
		if err != nil {
			return nil, err
		}
		v := view(o, false)
		v.SvcState, v.FirstSeen, v.LastSeen = state, first, last
		v.Annotation = ann[svcKey(o.IP, o.Port, o.Proto)]
		out = append(out, v)
	}
	return out, nil
}

const scanObsCols = scan.ObsCols

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	hs, err := s.hostRows(`WHERE h.ip=?`, ip)
	if err != nil || len(hs) == 0 {
		fail(w, 404, "brak hosta")
		return
	}
	svcs, _ := s.currentServices(`WHERE sv.ip=? ORDER BY sv.port`, ip)
	scans := []map[string]any{}
	rows, _ := s.S.DB.Query(`SELECT sh.scan_id,s.name,s.started_at,sh.alive,sh.reason,sh.retried FROM scan_hosts sh JOIN scans s ON s.id=sh.scan_id WHERE sh.ip=? ORDER BY sh.scan_id DESC LIMIT 30`, ip)
	for rows != nil && rows.Next() {
		var id int64
		var name, st, reason string
		var alive, retried int
		_ = rows.Scan(&id, &name, &st, &alive, &reason, &retried)
		scans = append(scans, map[string]any{"scan_id": id, "scan": name, "started_at": st, "alive": alive == 1, "reason": reason, "retried": retried == 1})
	}
	if rows != nil {
		rows.Close()
	}
	writeJSON(w, 200, map[string]any{"host": hs[0], "services": svcs, "scans": scans})
}

func (s *Server) listServices(w http.ResponseWriter, r *http.Request) {
	where, args := "WHERE 1=1", []any{}
	if st := r.URL.Query().Get("state"); st != "" {
		where += " AND sv.state=?"
		args = append(args, st)
	} else if r.URL.Query().Get("all") == "" && r.URL.Query().Get("host_view") != "down" {
		where += " AND sv.state!='gone'" // usługi hostów niewidocznych > 48 h pokazujemy z ostatniej obserwacji
	}
	svcs, err := s.currentServices(where+" ORDER BY sv.ip, sv.port", args...)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	q := r.URL.Query()
	// filtr wg widoku hosta (jak w zakładce Hosty): active | unstable | down
	if hv := q.Get("host_view"); hv != "" {
		ips := map[string]bool{}
		if hs, err := s.hostRows(""); err == nil {
			now := time.Now()
			for _, h := range hs {
				if hostView(h, now) == hv {
					ips[h.IP] = true
				}
			}
		}
		f := svcs[:0]
		for _, v := range svcs {
			if ips[v.IP] {
				f = append(f, v)
			}
		}
		svcs = f
	}
	out := []*obsView{}
	wantFlags := q.Get("flags")
	exact := qint(r, "interest", -1)
	for _, v := range svcs {
		if exact >= 0 && v.Interest != exact {
			continue
		}
		if q.Has("flags") && flagKey(v.Flags) != wantFlags {
			continue
		}
		if matchObs(v, q.Get("q"), q.Get("flag"), q.Get("tech"), qint(r, "min_interest", 0)) {
			if q.Get("hide_fp") == "1" && v.Annotation != nil && v.Annotation.FalsePositive {
				continue
			}
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Interest > out[j].Interest })
	writeJSON(w, 200, out)
}

// serviceGroups: grupowanie podobnych usług (produkt+wersja, technologia, tytuł, favicon).
func (s *Server) serviceGroups(w http.ResponseWriter, r *http.Request) {
	by := r.URL.Query().Get("by")
	svcs, err := s.currentServices(`WHERE sv.state!='gone'`)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	groups := map[string][]string{}
	for _, v := range svcs {
		var keys []string
		switch by {
		case "tech":
			for _, t := range v.Techs {
				keys = append(keys, t.Name)
			}
		case "title":
			if v.Title != "" {
				keys = []string{v.Title}
			}
		case "category":
			for _, t := range v.Techs {
				keys = append(keys, t.Category)
			}
		default:
			k := strings.TrimSpace(v.Service + " · " + v.Product + " " + v.Version)
			keys = []string{k}
		}
		for _, k := range uniq(keys) {
			groups[k] = append(groups[k], fmt.Sprintf("%s:%d", v.IP, v.Port))
		}
	}
	type g struct {
		Key     string   `json:"key"`
		Count   int      `json:"count"`
		Members []string `json:"members"`
	}
	out := []g{}
	for k, m := range groups {
		out = append(out, g{k, len(m), m})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	writeJSON(w, 200, out)
}

// technologies: inwentarz technologii w bieżących usługach (kategorie, technologie, rozkład wersji).
// technologies: zestawienie technologii. Zakres: mode=all (bieżący stan) | date (from,to: RRRR-MM-DD) | scans (from,to: id skanów).
// only_new=1: tylko technologie, które w katalogu (tabela technologies) pojawiły się pierwszy raz w tym zakresie.
func (s *Server) technologies(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	mode, onlyNew := q.Get("mode"), q.Get("only_new") == "1"
	type item struct {
		ip    string
		techs []scan.Tech
	}
	var items []item
	var fromTS, toTS string
	var fromScan, toScan int64
	switch mode {
	case "date", "scans":
		where, args := "", []any{}
		if mode == "date" {
			f, err1 := time.ParseInLocation("2006-01-02", q.Get("from"), time.Local)
			t, err2 := time.ParseInLocation("2006-01-02", q.Get("to"), time.Local)
			if err1 != nil || err2 != nil {
				fail(w, 400, "podaj daty od i do (RRRR-MM-DD)")
				return
			}
			if t.Before(f) {
				f, t = t, f
			}
			fromTS, toTS = f.UTC().Format(time.RFC3339), t.Add(24*time.Hour).UTC().Format(time.RFC3339)
			where, args = `WHERE seen_at >= ? AND seen_at < ? ORDER BY id DESC`, []any{fromTS, toTS}
		} else {
			fromScan, toScan = int64(qint(r, "from", 0)), int64(qint(r, "to", 0))
			if fromScan == 0 || toScan == 0 {
				fail(w, 400, "wybierz skan od i do")
				return
			}
			if toScan < fromScan {
				fromScan, toScan = toScan, fromScan
			}
			where, args = `WHERE scan_id BETWEEN ? AND ? ORDER BY id DESC`, []any{fromScan, toScan}
		}
		obs, err := scan.ListObs(s.S, where, false, args...)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		ann := s.annotations()
		seen := map[string]bool{}
		for _, o := range obs { // najnowsza obserwacja każdej usługi w zakresie
			k := fmt.Sprintf("%s:%d/%s", o.IP, o.Port, o.Proto)
			if seen[k] {
				continue
			}
			seen[k] = true
			if a := ann["svc:"+k]; a != nil && a.FalsePositive {
				continue
			}
			items = append(items, item{o.IP, o.Techs})
		}
	default:
		mode = "all"
		svcs, err := s.currentServices(`WHERE sv.state!='gone'`)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		for _, v := range svcs {
			if v.Annotation != nil && v.Annotation.FalsePositive {
				continue
			}
			items = append(items, item{v.IP, v.Techs})
		}
	}
	// katalog: pierwsze i ostatnie wystąpienie każdej technologii
	type first struct {
		at, last, status, decision string
		scan                       int64
	}
	catalog := map[string]first{}
	if rows, err := s.S.DB.Query(`SELECT id, COALESCE(first_seen,''), COALESCE(first_scan_id,0), COALESCE(last_seen,''), COALESCE(status,'new'), COALESCE(decision,'') FROM technologies`); err == nil {
		for rows.Next() {
			var id string
			var f first
			_ = rows.Scan(&id, &f.at, &f.scan, &f.last, &f.status, &f.decision)
			catalog[id] = f
		}
		rows.Close()
	}
	isNew := func(id string) bool {
		f, ok := catalog[id]
		if !ok {
			return false
		}
		switch mode {
		case "date":
			return f.at >= fromTS && f.at < toTS
		case "scans":
			return f.scan >= fromScan && f.scan <= toScan
		}
		return false
	}
	type ver struct {
		Version string `json:"version"`
		Count   int    `json:"count"`
	}
	type tech struct {
		ID        string         `json:"id"`
		Name      string         `json:"name"`
		Category  string         `json:"category"`
		Count     int            `json:"count"`
		Hosts     int            `json:"hosts"`
		AvgConf   int            `json:"avg_confidence"`
		Versions  []ver          `json:"versions"`
		FirstSeen string         `json:"first_seen"`
		FirstScan int64          `json:"first_scan_id"`
		LastSeen  string         `json:"last_seen"`
		New       bool           `json:"new"`
		Status    string         `json:"status"`   // new (do przejrzenia) | reviewed | ignored
		Decision  string         `json:"decision"` // znana | obserwuj | ignoruj
		vers      map[string]int `json:"-"`
		hosts     map[string]bool
		conf      int
	}
	techs := map[string]*tech{}
	cats := map[string]int{}
	for _, v := range items {
		for _, t := range v.techs {
			if onlyNew && !isNew(t.ID) {
				continue
			}
			x := techs[t.ID]
			if x == nil {
				f := catalog[t.ID]
				x = &tech{ID: t.ID, Name: t.Name, Category: t.Category, FirstSeen: f.at, FirstScan: f.scan, LastSeen: f.last, New: isNew(t.ID), Status: f.status, Decision: f.decision, vers: map[string]int{}, hosts: map[string]bool{}}
				techs[t.ID] = x
			}
			x.Count++
			x.conf += t.Confidence
			x.hosts[v.ip] = true
			vv := t.Version
			if vv == "" {
				vv = "?"
			}
			x.vers[vv]++
			cats[t.Category]++
		}
	}
	out := []*tech{}
	newCount := 0
	for _, x := range techs {
		x.Hosts = len(x.hosts)
		x.AvgConf = x.conf / max(1, x.Count)
		for k, c := range x.vers {
			x.Versions = append(x.Versions, ver{k, c})
		}
		sort.Slice(x.Versions, func(i, j int) bool { return x.Versions[i].Count > x.Versions[j].Count })
		if x.New {
			newCount++
		}
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	type cat struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
	}
	cl := []cat{}
	for k, c := range cats {
		cl = append(cl, cat{k, c})
	}
	sort.Slice(cl, func(i, j int) bool { return cl[i].Count > cl[j].Count })
	writeJSON(w, 200, map[string]any{"categories": cl, "technologies": out, "services": len(items), "mode": mode, "new_count": newCount, "catalog_size": len(catalog)})
}

// techReview: nowe technologie czekające na klasyfikację (status=new), z miejscem wystąpienia.
func (s *Server) techReview(w http.ResponseWriter, r *http.Request) {
	rows, err := s.S.DB.Query(`SELECT t.id, COALESCE(t.name,''), COALESCE(t.category,''), COALESCE(t.first_seen,''), COALESCE(t.first_scan_id,0),
COALESCE((SELECT COALESCE(NULLIF(sc.tag,''), (SELECT c.name FROM scan_configs c WHERE c.id=sc.config_id), '') FROM scans sc WHERE sc.id=t.first_scan_id),'')
FROM technologies t WHERE COALESCE(t.status,'new')='new' ORDER BY t.first_seen`)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	type item struct {
		ID        string   `json:"id"`
		Name      string   `json:"name"`
		Category  string   `json:"category"`
		FirstSeen string   `json:"first_seen"`
		FirstScan int64    `json:"first_scan_id"`
		ScanLabel string   `json:"first_scan_label"`
		Source    string   `json:"source"` // sygnatura | własna sygnatura | baner usługi
		Services  int      `json:"services"`
		Where     []string `json:"where"`
	}
	items := []*item{}
	idx := map[string]*item{}
	for rows.Next() {
		it := &item{Where: []string{}}
		_ = rows.Scan(&it.ID, &it.Name, &it.Category, &it.FirstSeen, &it.FirstScan, &it.ScanLabel)
		switch {
		case strings.HasPrefix(it.ID, "auto-"):
			it.Source = "baner usługi"
		case strings.HasPrefix(it.ID, "wlasna-"):
			it.Source = "własna sygnatura"
		default:
			it.Source = "sygnatura"
		}
		items = append(items, it)
		idx[it.ID] = it
	}
	rows.Close()
	if len(items) > 0 {
		if svcs, err := s.currentServices(`WHERE sv.state!='gone'`); err == nil {
			for _, v := range svcs {
				for _, t := range v.Techs {
					if it := idx[t.ID]; it != nil {
						it.Services++
						if len(it.Where) < 4 {
							it.Where = append(it.Where, fmt.Sprintf("%s:%d", v.IP, v.Port))
						}
					}
				}
			}
		}
	}
	writeJSON(w, 200, map[string]any{"count": len(items), "items": items})
}

// classifyTech: klasyfikacja nowej technologii przez analityka (znana / obserwuj / ignoruj).
func (s *Server) classifyTech(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var in struct {
		Decision string `json:"decision"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	status := map[string]string{"znana": "reviewed", "obserwuj": "reviewed", "ignoruj": "ignored"}[in.Decision]
	if status == "" {
		fail(w, 400, "decyzja: znana, obserwuj albo ignoruj")
		return
	}
	res, err := s.S.DB.Exec(`UPDATE technologies SET status=?, decision=?, reviewed_by=?, reviewed_at=? WHERE id=?`, status, in.Decision, user(r), store.Now(), id)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		fail(w, 404, "brak technologii w katalogu")
		return
	}
	s.S.Audit(user(r), "technology.classify", id, map[string]string{"decyzja": in.Decision})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ClassGroup: grupa usług o tej samej klasie i tym samym zestawie flag (dashboard i zakładka Usługi).
type ClassGroup struct {
	Interest int      `json:"interest"`
	Flags    []string `json:"flags"`
	FlagKey  string   `json:"flag_key"`
	Count    int      `json:"count"`
	Hosts    int      `json:"hosts"`
	Techs    []string `json:"techs"`
	Sample   []string `json:"sample"`
	hosts    map[string]bool
	techs    map[string]int
}

func classGroups(top []*obsView) []*ClassGroup {
	groups := map[string]*ClassGroup{}
	for _, v := range top {
		k := fmt.Sprintf("%d|%s", v.Interest, flagKey(v.Flags))
		g := groups[k]
		if g == nil {
			g = &ClassGroup{Interest: v.Interest, Flags: append([]string{}, v.Flags...), FlagKey: flagKey(v.Flags), hosts: map[string]bool{}, techs: map[string]int{}}
			sort.Strings(g.Flags)
			groups[k] = g
		}
		g.Count++
		g.hosts[v.IP] = true
		for _, t := range v.Techs {
			if t.Category != "server" && t.Category != "language" {
				g.techs[t.Name]++
			}
		}
		if len(g.Sample) < 3 {
			g.Sample = append(g.Sample, fmt.Sprintf("%s:%d", v.IP, v.Port))
		}
	}
	gl := []*ClassGroup{}
	for _, g := range groups {
		g.Hosts = len(g.hosts)
		type tc struct {
			n string
			c int
		}
		var ts []tc
		for n, c := range g.techs {
			ts = append(ts, tc{n, c})
		}
		sort.Slice(ts, func(i, j int) bool { return ts[i].c > ts[j].c || ts[i].c == ts[j].c && ts[i].n < ts[j].n })
		for i := 0; i < len(ts) && i < 4; i++ {
			g.Techs = append(g.Techs, ts[i].n)
		}
		if g.Techs == nil {
			g.Techs = []string{}
		}
		gl = append(gl, g)
	}
	sort.Slice(gl, func(i, j int) bool {
		if gl[i].Interest != gl[j].Interest {
			return gl[i].Interest > gl[j].Interest
		}
		if gl[i].Count != gl[j].Count {
			return gl[i].Count > gl[j].Count
		}
		return gl[i].FlagKey < gl[j].FlagKey
	})
	return gl
}

// serviceClassGroups: wszystkie grupy (klasa + flagi) bieżących usług, z filtrami jak lista usług.
func (s *Server) serviceClassGroups(w http.ResponseWriter, r *http.Request) {
	svcs, err := s.currentServices(`WHERE sv.state!='gone'`)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	q := r.URL.Query()
	list := []*obsView{}
	for _, v := range svcs {
		if q.Get("hide_fp") == "1" && v.Annotation != nil && v.Annotation.FalsePositive {
			continue
		}
		if matchObs(v, q.Get("q"), q.Get("flag"), q.Get("tech"), qint(r, "min_interest", 0)) {
			list = append(list, v)
		}
	}
	writeJSON(w, 200, classGroups(list))
}

func flagKey(f []string) string {
	c := append([]string{}, f...)
	sort.Strings(c)
	return strings.Join(c, ",")
}

// ---- diff ----

func (s *Server) latestTwo(cfgID int64) (int64, int64) {
	var ids []int64
	q := `SELECT id FROM scans WHERE status='completed' AND source!='retry' ORDER BY id DESC LIMIT 2`
	var rows *sql.Rows
	if cfgID > 0 {
		rows, _ = s.S.DB.Query(`SELECT id FROM scans WHERE status='completed' AND source!='retry' AND config_id=? ORDER BY id DESC LIMIT 2`, cfgID)
	} else {
		rows, _ = s.S.DB.Query(q)
	}
	for rows != nil && rows.Next() {
		var id int64
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	if rows != nil {
		rows.Close()
	}
	if len(ids) < 2 {
		return 0, 0
	}
	return ids[1], ids[0]
}

// diffTimeline: oś czasu zmian dla reguły: podsumowanie różnic każdej pary kolejnych skanów (ostatnie n).
func (s *Server) diffTimeline(w http.ResponseWriter, r *http.Request) {
	cfg, _ := strconv.ParseInt(r.URL.Query().Get("config"), 10, 64)
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	n = max(2, min(30, n))
	if n == 2 {
		n = 12
	}
	type pt struct {
		A        int64          `json:"a"`
		B        int64          `json:"b"`
		At       string         `json:"at"`
		Summary  map[string]int `json:"summary"`
		Compared int            `json:"compared_ips"` // 0 = skany nie mają wspólnych adresów (inny zakres celów)
	}
	out := []pt{}
	rows, err := s.S.DB.Query(`SELECT id, COALESCE(NULLIF(finished_at,''),created_at) FROM scans WHERE status='completed' AND source!='retry' AND config_id=? ORDER BY id DESC LIMIT ?`, cfg, n+1)
	if err != nil {
		writeJSON(w, 200, out)
		return
	}
	var ids []int64
	var ats []string
	for rows.Next() {
		var id int64
		var at string
		_ = rows.Scan(&id, &at)
		ids, ats = append(ids, id), append(ats, at)
	}
	rows.Close()
	for i := len(ids) - 1; i > 0; i-- {
		if d, err := diff.Compute(s.S, ids[i], ids[i-1]); err == nil {
			out = append(out, pt{A: ids[i], B: ids[i-1], At: ats[i-1], Summary: d.Summary, Compared: d.ComparedIPs})
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) diffFor(r *http.Request) (*diff.Result, error) {
	a, _ := strconv.ParseInt(r.URL.Query().Get("a"), 10, 64)
	b, _ := strconv.ParseInt(r.URL.Query().Get("b"), 10, 64)
	if a == 0 || b == 0 {
		cfg, _ := strconv.ParseInt(r.URL.Query().Get("config"), 10, 64)
		a, b = s.latestTwo(cfg)
		if a == 0 {
			return nil, fmt.Errorf("potrzebne są co najmniej dwa zakończone skany")
		}
	}
	return diff.Compute(s.S, a, b)
}

func (s *Server) diff(w http.ResponseWriter, r *http.Request) {
	d, err := s.diffFor(r)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, d)
}

// ---- dashboard ----

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	hostStates := map[string]int{}
	rows, _ := s.S.DB.Query(`SELECT state,COUNT(*) FROM hosts GROUP BY state`)
	for rows != nil && rows.Next() {
		var st string
		var n int
		_ = rows.Scan(&st, &n)
		hostStates[st] = n
	}
	if rows != nil {
		rows.Close()
	}
	out["host_states"] = hostStates
	svcStates := map[string]int{}
	rows, _ = s.S.DB.Query(`SELECT state,COUNT(*) FROM services GROUP BY state`)
	for rows != nil && rows.Next() {
		var st string
		var n int
		_ = rows.Scan(&st, &n)
		svcStates[st] = n
	}
	if rows != nil {
		rows.Close()
	}
	out["service_states"] = svcStates
	var targetsN, scansN int
	_ = s.S.DB.QueryRow(`SELECT COUNT(*) FROM targets WHERE enabled=1`).Scan(&targetsN)
	_ = s.S.DB.QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&scansN)
	out["targets"], out["scans"] = targetsN, scansN

	svcs, _ := s.currentServices(`WHERE sv.state!='gone'`)
	flags, cats, techs := map[string]int{}, map[string]int{}, map[string]int{}
	top := []*obsView{}
	interesting := 0
	for _, v := range svcs {
		if v.Annotation != nil && v.Annotation.FalsePositive {
			continue
		}
		if v.Interest >= 25 {
			interesting++
		}
		for _, f := range v.Flags {
			flags[f]++
		}
		for _, t := range v.Techs {
			cats[t.Category]++
			techs[t.Name]++
		}
		top = append(top, v)
	}
	allGroups := classGroups(top)
	gl := []*ClassGroup{}
	for _, g := range allGroups {
		if g.Interest > 0 {
			gl = append(gl, g)
		}
	}
	if len(gl) > 15 {
		gl = gl[:15]
	}
	out["top_groups"] = gl
	sort.SliceStable(top, func(i, j int) bool { return top[i].Interest > top[j].Interest })
	if len(top) > 12 {
		top = top[:12]
	}
	out["top_services"], out["flags"], out["categories"], out["technologies"] = top, flags, cats, techs
	out["interesting_count"] = interesting
	out["host_views"] = s.hostViewCounts()

	unstable, _ := s.hostRows(`WHERE h.state IN ('unstable','missing','unreachable') ORDER BY h.last_seen DESC LIMIT 20`)
	retry := []map[string]any{}
	rr, _ := s.S.DB.Query(`SELECT id,name,live_hosts,total_ips,open_services,finished_at,windows FROM scans WHERE source='retry' ORDER BY id DESC LIMIT 3`)
	for rr != nil && rr.Next() {
		var id int64
		var name, fin string
		var live, total, svc, win int
		_ = rr.Scan(&id, &name, &live, &total, &svc, &fin, &win)
		retry = append(retry, map[string]any{"id": id, "name": name, "found": live, "checked": total, "services": svc, "last": fin, "batches": win})
	}
	if rr != nil {
		rr.Close()
	}
	out["retry_scans"] = retry
	out["unstable_hosts"] = unstable
	patterned := []*hostOut{}
	all, _ := s.hostRows(`WHERE h.scan_count>=3`)
	for _, h := range all {
		if h.DayPattern != "" {
			patterned = append(patterned, h)
		}
	}
	out["day_pattern_hosts"] = patterned

	// porównanie w obrębie tej samej reguły co najnowszy skan (inaczej porównanie różnych zakresów daje 0 adresów)
	var lastCfg int64
	_ = s.S.DB.QueryRow(`SELECT COALESCE(config_id,0) FROM scans WHERE status='completed' AND source!='retry' ORDER BY id DESC LIMIT 1`).Scan(&lastCfg)
	a, b := s.latestTwo(lastCfg)
	if a == 0 {
		a, b = s.latestTwo(0)
	}
	if a > 0 {
		if d, err := diff.Compute(s.S, a, b); err == nil {
			if len(d.Services) > 15 {
				d.Services = d.Services[:15]
			}
			if len(d.Hosts) > 15 {
				d.Hosts = d.Hosts[:15]
			}
			out["latest_diff"] = d
		}
	}
	running := []*scanOut{}
	rs, _ := s.S.DB.Query(`SELECT ` + scanColsSQL + ` FROM scans WHERE status IN ('running','queued','paused') ORDER BY id DESC LIMIT 5`)
	for rs != nil && rs.Next() {
		if o, err := s.scanRow(rs); err == nil {
			running = append(running, o)
		}
	}
	if rs != nil {
		rs.Close()
	}
	out["active_scans"] = running
	trend := []map[string]any{}
	tr, _ := s.S.DB.Query(`SELECT id,name,started_at,live_hosts,open_services,total_ips,elapsed_ms FROM scans WHERE status='completed' AND source!='retry' ORDER BY id DESC LIMIT 20`)
	for tr != nil && tr.Next() {
		var id int64
		var name, st string
		var live, svc, total int
		var ms int64
		_ = tr.Scan(&id, &name, &st, &live, &svc, &total, &ms)
		trend = append([]map[string]any{{"id": id, "name": name, "started_at": st, "live_hosts": live, "open_services": svc, "total_ips": total, "elapsed_ms": ms}}, trend...)
	}
	if tr != nil {
		tr.Close()
	}
	out["trend"] = trend
	writeJSON(w, 200, out)
}
