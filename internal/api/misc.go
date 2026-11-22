package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/asi-agh/asi/internal/dojo"
	"github.com/asi-agh/asi/internal/export"
	"github.com/asi-agh/asi/internal/ports"
	"github.com/asi-agh/asi/internal/scan"
	"github.com/asi-agh/asi/internal/sig"
	"github.com/asi-agh/asi/internal/store"
)

func sigDetection(t scan.Tech) sig.Detection {
	return sig.Detection{ID: t.ID, Name: t.Name, Category: t.Category, Version: t.Version, Confidence: t.Confidence, Evidence: []string{"edycja ręczna"}}
}

// ---- sygnatury ----

// SyncSignatures: przy starcie dopisuje brakujące sygnatury wbudowane i ładuje włączone sygnatury do silnika.
func SyncSignatures(s *store.Store, e *sig.Engine) error {
	builtin, err := sig.ParseYAML(sig.BuiltinYAML)
	if err != nil {
		return err
	}
	for _, b := range builtin {
		body, _ := yaml.Marshal(b)
		// nowe wersje sygnatur wbudowanych nadpisują stare, chyba że użytkownik je zmodyfikował
		_, _ = s.DB.Exec(`INSERT INTO signatures(sid,name,category,enabled,builtin,body,created_by,updated_at) VALUES(?,?,?,1,1,?,?,?)
ON CONFLICT(sid) DO UPDATE SET body=excluded.body, name=excluded.name, category=excluded.category
WHERE signatures.builtin=1 AND signatures.created_by='system'`, b.ID, b.Name, b.Category, string(body), "system", store.Now())
	}
	return ReloadSignatures(s, e)
}

func ReloadSignatures(s *store.Store, e *sig.Engine) error {
	defer func() { _ = scan.SyncRules(s.DB, e.All()) }() // każda sygnatura ma regułę klasy
	rows, err := s.DB.Query(`SELECT body FROM signatures WHERE enabled=1 ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var list []sig.Signature
	for rows.Next() {
		var body string
		_ = rows.Scan(&body)
		ss, err := sig.ParseYAML([]byte(body))
		if err == nil {
			list = append(list, ss...)
		}
	}
	e.Set(list)
	return nil
}

func (s *Server) listSigs(w http.ResponseWriter, r *http.Request) {
	rows, err := s.S.DB.Query(`SELECT id,sid,name,category,enabled,builtin,body,created_by,updated_at FROM signatures ORDER BY builtin, category, name`)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var sid, name, cat, body, by, at string
		var en, b int
		_ = rows.Scan(&id, &sid, &name, &cat, &en, &b, &body, &by, &at)
		out = append(out, map[string]any{"id": id, "sid": sid, "name": name, "category": cat, "enabled": en == 1, "builtin": b == 1, "body": body, "created_by": by, "updated_at": at})
	}
	writeJSON(w, 200, out)
}

func (s *Server) saveSig(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	var in struct {
		Body    string `json:"body"`
		Enabled *bool  `json:"enabled"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	if id != 0 && in.Body == "" && in.Enabled != nil {
		_, _ = s.S.DB.Exec(`UPDATE signatures SET enabled=?, updated_at=? WHERE id=?`, boolInt(*in.Enabled), store.Now(), id)
		_ = ReloadSignatures(s.S, s.Sigs)
		s.S.Audit(user(r), "signature.toggle", strconv.FormatInt(id, 10), map[string]bool{"enabled": *in.Enabled})
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	list, err := sig.ParseYAML([]byte(in.Body))
	if err != nil {
		fail(w, 400, "błąd sygnatury: "+err.Error())
		return
	}
	if len(list) != 1 {
		fail(w, 400, "zapisz jedną sygnaturę naraz")
		return
	}
	sg := list[0]
	en := 1
	if in.Enabled != nil && !*in.Enabled {
		en = 0
	}
	if id == 0 {
		_, err = s.S.DB.Exec(`INSERT INTO signatures(sid,name,category,enabled,builtin,body,created_by,updated_at) VALUES(?,?,?,?,0,?,?,?)`,
			sg.ID, sg.Name, sg.Category, en, in.Body, user(r), store.Now())
	} else {
		_, err = s.S.DB.Exec(`UPDATE signatures SET sid=?, name=?, category=?, enabled=?, body=?, updated_at=?, created_by=? WHERE id=?`,
			sg.ID, sg.Name, sg.Category, en, in.Body, store.Now(), user(r), id)
	}
	if err != nil {
		fail(w, 400, "sygnatura o tym id już istnieje")
		return
	}
	_ = ReloadSignatures(s.S, s.Sigs)
	s.S.Audit(user(r), "signature.save", sg.ID, nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) deleteSig(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	var b int
	_ = s.S.DB.QueryRow(`SELECT builtin FROM signatures WHERE id=?`, id).Scan(&b)
	if b == 1 {
		fail(w, 400, "sygnatur wbudowanych nie usuwamy: wyłącz ją")
		return
	}
	_, _ = s.S.DB.Exec(`DELETE FROM signatures WHERE id=?`, id)
	_ = ReloadSignatures(s.S, s.Sigs)
	s.S.Audit(user(r), "signature.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// testSig: sprawdzenie sygnatury na zapisanych wynikach (bez wysyłania ruchu do sieci).
func (s *Server) testSig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Body   string `json:"body"`
		ScanID int64  `json:"scan_id"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	list, err := sig.ParseYAML([]byte(in.Body))
	if err != nil {
		writeJSON(w, 200, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	var obs []*scan.Observation
	if in.ScanID > 0 {
		obs, err = scan.ListObs(s.S, `WHERE scan_id=?`, true, in.ScanID)
	} else {
		obs, err = scan.ListObs(s.S, `WHERE id IN (SELECT last_obs_id FROM services)`, true)
	}
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	hits := []map[string]any{}
	for _, o := range obs {
		if o.Data.HTTP != nil {
			o.Data.HTTP.Body = o.Data.HTTP.BodySnippet
		}
		in := scan.SigInput(o)
		for i := range list {
			if d, ok := sig.Eval(&list[i], in); ok {
				hits = append(hits, map[string]any{"obs_id": o.ID, "ip": o.IP, "port": o.Port, "detection": d})
			}
		}
	}
	note := ""
	for _, sg := range list {
		for _, m := range sg.Matchers {
			if m.Type == "path" {
				note = "matchery typu path są sprawdzane podczas skanu (test działa na zapisanych odpowiedziach)"
			}
		}
	}
	writeJSON(w, 200, map[string]any{"valid": true, "tested": len(obs), "hits": hits, "note": note})
}

// ---- import / eksport ----

func (s *Server) importResults(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(128 << 20); err != nil {
		fail(w, 400, "oczekiwano pliku (multipart/form-data)")
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		fail(w, 400, "brak pliku")
		return
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, 128<<20))
	p, err := export.ParseResults(data, hdr.Filename)
	if err != nil {
		fail(w, 400, "nie udało się odczytać pliku: "+err.Error())
		return
	}
	name := r.FormValue("name")
	if name == "" {
		name = "Import " + hdr.Filename + " · " + time.Now().Format("2006-01-02 15:04")
	}
	id, skipped, err := s.E.ImportResults(name, user(r), p.Format, p.Ports, p.Alive, p.Obs, nil)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.S.Audit(user(r), "results.import", hdr.Filename, map[string]any{"scan_id": id, "format": p.Format, "hosts": len(p.Alive), "services": len(p.Obs)})
	writeJSON(w, 200, map[string]any{"scan_id": id, "format": p.Format, "hosts": len(p.Alive), "services": len(p.Obs), "skipped": skipped, "notes": p.Notes})
}

func (s *Server) annotateRecords(recs []export.Record) {
	ann := s.annotations()
	for i := range recs {
		if a := ann[svcKey(recs[i].IP, recs[i].Port, recs[i].Proto)]; a != nil {
			recs[i].Tags, recs[i].Note = a.Tags, a.Note
		}
	}
}

func sendExport(w http.ResponseWriter, format, name string, doc export.Document) {
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, name))
		_, _ = w.Write([]byte("\xef\xbb\xbf"))
		_ = export.WriteCSV(w, doc.Records)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, name))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(doc)
}

func (s *Server) exportScan(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	so, err := s.scanRow(s.S.DB.QueryRow(`SELECT `+scanColsSQL+` FROM scans WHERE id=?`, id))
	if err != nil {
		fail(w, 404, "brak skanu")
		return
	}
	obs, err := scan.ListObs(s.S, `WHERE scan_id=? ORDER BY ip, port`, true, id)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	doc := export.Document{Format: export.FormatVersion, ExportedAt: store.Now(), Scan: so, Hosts: []string{}, Records: []export.Record{}}
	rows, _ := s.S.DB.Query(`SELECT ip FROM scan_hosts WHERE scan_id=? AND alive=1 ORDER BY ip`, id)
	for rows != nil && rows.Next() {
		var ip string
		_ = rows.Scan(&ip)
		doc.Hosts = append(doc.Hosts, ip)
	}
	if rows != nil {
		rows.Close()
	}
	for _, o := range obs {
		doc.Records = append(doc.Records, export.ToRecord(o))
	}
	s.annotateRecords(doc.Records)
	s.S.Audit(user(r), "export.scan", strconv.FormatInt(id, 10), map[string]string{"format": r.URL.Query().Get("format")})
	sendExport(w, r.URL.Query().Get("format"), fmt.Sprintf("asi-scan-%d", id), doc)
}

func (s *Server) exportServices(w http.ResponseWriter, r *http.Request) {
	svcs, err := s.currentServices(`WHERE sv.state!='gone' ORDER BY sv.ip, sv.port`)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	doc := export.Document{Format: export.FormatVersion, ExportedAt: store.Now(), Hosts: []string{}, Records: []export.Record{}}
	seen := map[string]bool{}
	for _, v := range svcs {
		o, err := scan.GetObs(s.S, v.ID)
		if err != nil {
			continue
		}
		if !seen[o.IP] {
			seen[o.IP] = true
			doc.Hosts = append(doc.Hosts, o.IP)
		}
		doc.Records = append(doc.Records, export.ToRecord(o))
	}
	s.annotateRecords(doc.Records)
	s.S.Audit(user(r), "export.services", "", nil)
	sendExport(w, r.URL.Query().Get("format"), "asi-inventory", doc)
}

func (s *Server) exportTargets(w http.ResponseWriter, r *http.Request) {
	ts, err := s.loadTargets()
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="asi-targets.csv"`)
		var b bytes.Buffer
		b.WriteString("value,tags,note,enabled\n")
		for _, t := range ts {
			fmt.Fprintf(&b, "%s,%s,%q,%v\n", t.Value, strings.Join(t.Tags, "|"), t.Note, t.Enabled)
		}
		_, _ = w.Write(b.Bytes())
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="asi-targets.json"`)
	writeJSON(w, 200, map[string]any{"targets": ts})
}

func (s *Server) exportDiff(w http.ResponseWriter, r *http.Request) {
	d, err := s.diffFor(r)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="asi-diff-%d-%d.csv"`, d.A.ID, d.B.ID))
		var b bytes.Buffer
		b.WriteString("\xef\xbb\xbftyp,obiekt,ip,port,proto,usluga,produkt,zmiany\n")
		for _, h := range d.Hosts {
			fmt.Fprintf(&b, "%s,host,%s,,,,,\n", h.Kind, h.IP)
		}
		for _, x := range d.Services {
			var ch []string
			for _, c := range x.Changes {
				ch = append(ch, fmt.Sprintf("%s: %s → %s", c.Field, c.Before, c.After))
			}
			fmt.Fprintf(&b, "%s,usluga,%s,%d,%s,%s,%q,%q\n", x.Kind, x.IP, x.Port, x.Proto, x.Service, x.Product, strings.Join(ch, "; "))
		}
		_, _ = w.Write(b.Bytes())
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="asi-diff-%d-%d.json"`, d.A.ID, d.B.ID))
	writeJSON(w, 200, d)
}

// ---- DefectDojo ----

func (s *Server) dojoSettings() dojo.Settings {
	var st dojo.Settings
	_ = json.Unmarshal([]byte(s.S.GetSetting("dojo")), &st)
	return st
}

func (s *Server) getDojo(w http.ResponseWriter, r *http.Request) {
	st := s.dojoSettings()
	hasToken := st.Token != ""
	st.Token = ""
	writeJSON(w, 200, map[string]any{"settings": st, "has_token": hasToken})
}

func (s *Server) putDojo(w http.ResponseWriter, r *http.Request) {
	var in dojo.Settings
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	cur := s.dojoSettings()
	if in.Token == "" {
		in.Token = cur.Token // token tylko do zapisu: puste pole = bez zmian
	}
	b, _ := json.Marshal(in)
	if err := s.S.SetSetting("dojo", string(b)); err != nil {
		fail(w, 500, err.Error())
		return
	}
	s.S.Audit(user(r), "settings.dojo", in.URL, nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) testDojo(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := dojo.Test(ctx, s.dojoSettings()); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) dojoObs(scanID int64, ids []int64, minInterest int) ([]*scan.Observation, string, error) {
	var obs []*scan.Observation
	var err error
	name := "MoNet"
	switch {
	case len(ids) > 0:
		for _, id := range ids {
			if o, e := scan.GetObs(s.S, id); e == nil {
				obs = append(obs, o)
			}
		}
	case scanID > 0:
		obs, err = scan.ListObs(s.S, `WHERE scan_id=? AND interest>=? ORDER BY interest DESC`, true, scanID, minInterest)
		_ = s.S.DB.QueryRow(`SELECT name FROM scans WHERE id=?`, scanID).Scan(&name)
	default:
		obs, err = scan.ListObs(s.S, `WHERE id IN (SELECT last_obs_id FROM services WHERE state!='gone') AND interest>=?`, true, minInterest)
	}
	return scan.WithoutFalsePositives(s.S.DB, obs), name, err
}

func (s *Server) previewDojo(w http.ResponseWriter, r *http.Request) {
	sid, _ := strconv.ParseInt(r.URL.Query().Get("scan_id"), 10, 64)
	obs, _, err := s.dojoObs(sid, nil, qint(r, "min_interest", 20))
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="asi-defectdojo-generic.json"`)
	}
	_, _ = w.Write(dojo.GenericJSON(obs))
}

func (s *Server) pushDojo(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ScanID      int64   `json:"scan_id"`
		IDs         []int64 `json:"observation_ids"`
		MinInterest int     `json:"min_interest"`
		Reimport    bool    `json:"reimport"`
		TestTitle   string  `json:"test_title"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	obs, name, err := s.dojoObs(in.ScanID, in.IDs, in.MinInterest)
	obs = scan.WithoutFalsePositives(s.S.DB, obs) // fałszywe alarmy nie trafiają do DefectDojo
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	var res map[string]any
	mode, title := "import", name
	if in.Reimport {
		mode, title = "reimport", in.TestTitle
		if title == "" {
			title = "MoNet – inwentarz"
		}
		res, err = dojo.Reimport(ctx, s.dojoSettings(), obs, title)
	} else {
		res, err = dojo.Push(ctx, s.dojoSettings(), obs, name)
	}
	dojo.Record(s.S.DB, user(r), in.ScanID, mode, title, len(obs), res, err)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.S.Audit(user(r), "dojo.push", strconv.FormatInt(in.ScanID, 10), map[string]int{"findings": len(obs)})
	writeJSON(w, 200, map[string]any{"sent": len(obs), "response": res})
}

// ---- audyt ----

// ---- dziennik logów (tabela audit: wpisy trwałe, nic ich nie kasuje) ----

type auditRow struct {
	ID     int64  `json:"id"`
	TS     string `json:"ts"`
	User   string `json:"user"`
	Action string `json:"action"`
	Entity string `json:"entity"`
	Detail string `json:"detail"`
}

// localDay: dzień wpisu w czasie lokalnym serwera (Europe/Warsaw), np. 2026-11-21.
func localDay(ts string) string {
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.Local().Format("2006-01-02")
	}
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ""
}

func (s *Server) auditRows(day string, limit int) []auditRow {
	q, args := `SELECT id,ts,username,action,entity,detail FROM audit ORDER BY id DESC LIMIT ?`, []any{limit}
	if day != "" {
		// zapas ±1 dzień w UTC, dokładny filtr po dniu lokalnym niżej
		d, err := time.ParseInLocation("2006-01-02", day, time.Local)
		if err != nil {
			return []auditRow{}
		}
		from, to := d.Add(-24*time.Hour).UTC().Format(time.RFC3339), d.Add(48*time.Hour).UTC().Format(time.RFC3339)
		q, args = `SELECT id,ts,username,action,entity,detail FROM audit WHERE ts >= ? AND ts < ? ORDER BY id DESC`, []any{from, to}
	}
	rows, err := s.S.DB.Query(q, args...)
	if err != nil {
		return []auditRow{}
	}
	defer rows.Close()
	out := []auditRow{}
	for rows.Next() {
		var a auditRow
		_ = rows.Scan(&a.ID, &a.TS, &a.User, &a.Action, &a.Entity, &a.Detail)
		if day == "" || localDay(a.TS) == day {
			out = append(out, a)
		}
	}
	return out
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.auditRows(r.URL.Query().Get("day"), qint(r, "limit", 300)))
}

// auditDays: lista dni z liczbą wpisów i nieudanych logowań (najnowsze na górze).
func (s *Server) auditDays(w http.ResponseWriter, r *http.Request) {
	rows, err := s.S.DB.Query(`SELECT ts, action FROM audit`)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type day struct {
		Day   string `json:"day"`
		Count int    `json:"count"`
		Fails int    `json:"login_fails"`
	}
	m := map[string]*day{}
	for rows.Next() {
		var ts, act string
		_ = rows.Scan(&ts, &act)
		d := localDay(ts)
		if m[d] == nil {
			m[d] = &day{Day: d}
		}
		m[d].Count++
		if act == "login.fail" {
			m[d].Fails++
		}
	}
	out := make([]*day, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Day > out[j].Day })
	writeJSON(w, 200, out)
}

// exportAudit: pobranie logów z całego dnia (CSV albo JSON).
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	day := r.URL.Query().Get("day")
	var list []auditRow
	if day == "all" {
		list = s.auditRows("", 1<<30) // cały dziennik
		day = "wszystkie"
	} else if _, err := time.Parse("2006-01-02", day); err != nil {
		fail(w, 400, "podaj dzień w formacie RRRR-MM-DD albo all")
		return
	} else {
		list = s.auditRows(day, 0)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID }) // chronologicznie
	s.S.Audit(user(r), "audit.export", day, map[string]any{"wpisow": len(list), "format": r.URL.Query().Get("format")})
	name := "monet-logi-" + day
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.json"`)
		writeJSON(w, 200, map[string]any{"day": day, "count": len(list), "entries": list})
		return
	}
	if r.URL.Query().Get("format") == "txt" {
		// zwykły tekst: jedna linia na wpis, czas lokalny
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.txt"`)
		fmt.Fprintf(w, "MoNet: dziennik logów (%s, %d wpisów)\n\n", day, len(list))
		for _, a := range list {
			loc := a.TS
			if t, err := time.Parse(time.RFC3339, a.TS); err == nil {
				loc = t.Local().Format("2006-01-02 15:04:05")
			}
			u := a.User
			if u == "" {
				u = "-"
			}
			line := fmt.Sprintf("%s  %-12s %-22s", loc, u, a.Action)
			if a.Entity != "" {
				line += " " + a.Entity
			}
			if a.Detail != "" && a.Detail != "null" {
				line += "  " + a.Detail
			}
			fmt.Fprintln(w, line)
		}
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "czas_utc", "czas_lokalny", "uzytkownik", "akcja", "obiekt", "szczegoly"})
	for _, a := range list {
		loc := a.TS
		if t, err := time.Parse(time.RFC3339, a.TS); err == nil {
			loc = t.Local().Format("2006-01-02 15:04:05")
		}
		_ = cw.Write(export.SafeRow([]string{strconv.FormatInt(a.ID, 10), a.TS, loc, a.User, a.Action, a.Entity, a.Detail}))
	}
	cw.Flush()
}

// ---- reguły klasy ----

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	rows, err := s.S.DB.Query(`SELECT id,kind,key,name,weight,enabled,auto,reviewed,created_at FROM scoring_rules ORDER BY kind, weight DESC, key`)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	defer rows.Close()
	list := []*scan.Rule{}
	idx := map[string]*scan.Rule{}
	for rows.Next() {
		x := &scan.Rule{}
		var e, a, rv int
		_ = rows.Scan(&x.ID, &x.Kind, &x.Key, &x.Name, &x.Weight, &e, &a, &rv, &x.Created)
		x.Enabled, x.Auto, x.Reviewed = e == 1, a == 1, rv == 1
		list = append(list, x)
		idx[x.Kind+":"+x.Key] = x
	}
	rows.Close()
	// ile bieżących usług dopasowuje każdą regułę
	svcs, _ := s.currentServices(`WHERE sv.state!='gone'`)
	for _, v := range svcs {
		for _, t := range v.Techs {
			if x := idx["signature:"+t.ID]; x != nil {
				x.Matches++
			}
		}
		for _, k := range v.Rules {
			if strings.HasPrefix(k, "heuristic:") {
				if x := idx[k]; x != nil {
					x.Matches++
				}
			}
		}
		if x := idx[fmt.Sprintf("port:%s/%d", v.Proto, v.Port)]; x != nil {
			x.Matches++
		}
	}
	writeJSON(w, 200, map[string]any{"rules": list, "enabled": scan.ActiveRules().Enabled()})
}

func (s *Server) afterRules(w http.ResponseWriter, r *http.Request, action, entity string, detail any) {
	_ = scan.LoadRules(s.S.DB)
	n, err := s.E.Rescore()
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	s.S.Audit(user(r), action, entity, detail)
	writeJSON(w, 200, map[string]any{"ok": true, "rescored": n})
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Proto  string `json:"proto"`
		Port   int    `json:"port"`
		Name   string `json:"name"`
		Weight int    `json:"weight"`
	}
	if err := readJSON(r, &in); err != nil || in.Port < 1 || in.Port > 65535 {
		fail(w, 400, "podaj port 1–65535")
		return
	}
	if in.Proto != "udp" {
		in.Proto = "tcp"
	}
	key := fmt.Sprintf("%s/%d", in.Proto, in.Port)
	if in.Name == "" {
		in.Name = "Port " + key
	}
	_, err := s.S.DB.Exec(`INSERT INTO scoring_rules(kind,key,name,weight,enabled,auto,reviewed,created_at) VALUES('port',?,?,?,1,0,1,?)
ON CONFLICT(kind,key) DO UPDATE SET name=excluded.name, weight=excluded.weight, reviewed=1`, key, in.Name, max(0, min(100, in.Weight)), store.Now())
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.afterRules(w, r, "rule.create", key, in)
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	var in struct {
		Weight   *int    `json:"weight"`
		Enabled  *bool   `json:"enabled"`
		Reviewed *bool   `json:"reviewed"`
		Name     *string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	if in.Weight != nil {
		_, _ = s.S.DB.Exec(`UPDATE scoring_rules SET weight=?, reviewed=1 WHERE id=?`, max(0, min(100, *in.Weight)), id)
	}
	if in.Enabled != nil {
		_, _ = s.S.DB.Exec(`UPDATE scoring_rules SET enabled=? WHERE id=?`, boolInt(*in.Enabled), id)
	}
	if in.Reviewed != nil {
		_, _ = s.S.DB.Exec(`UPDATE scoring_rules SET reviewed=? WHERE id=?`, boolInt(*in.Reviewed), id)
	}
	if in.Name != nil {
		_, _ = s.S.DB.Exec(`UPDATE scoring_rules SET name=? WHERE id=?`, *in.Name, id)
	}
	s.afterRules(w, r, "rule.update", strconv.FormatInt(id, 10), in)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	var kind string
	_ = s.S.DB.QueryRow(`SELECT kind FROM scoring_rules WHERE id=?`, id).Scan(&kind)
	if kind != "port" {
		fail(w, 400, "usuwać można tylko reguły portów: pozostałe wyłącz")
		return
	}
	_, _ = s.S.DB.Exec(`DELETE FROM scoring_rules WHERE id=?`, id)
	s.afterRules(w, r, "rule.delete", strconv.FormatInt(id, 10), nil)
}

func (s *Server) rescore(w http.ResponseWriter, r *http.Request) {
	s.afterRules(w, r, "rule.rescore", "", nil)
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	p := scan.LoadPolicy(s.S)
	if p.AllowCIDRs == nil {
		p.AllowCIDRs = []string{}
	}
	writeJSON(w, 200, p)
}

func (s *Server) putPolicy(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("reset") == "1" {
		_ = s.S.SetSetting("scan_policy", "")
		s.S.Audit(user(r), "settings.scan_policy", "reset", nil)
		writeJSON(w, 200, scan.LoadPolicy(s.S))
		return
	}
	var in struct {
		scan.Policy
		ConfirmAny bool `json:"confirm_any"` // świadoma zgoda na brak listy sieci (dowolne adresy, także publiczne)
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	p := in.Policy
	if err := p.Normalize(); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if len(p.AllowCIDRs) == 0 && !in.ConfirmAny {
		fail(w, 400, "pusta lista sieci oznacza zgodę na dowolne adresy; potwierdź (confirm_any) albo podaj sieci")
		return
	}
	if p.AllowCIDRs == nil {
		p.AllowCIDRs = []string{}
	}
	b, _ := json.Marshal(p)
	if err := s.S.SetSetting("scan_policy", string(b)); err != nil {
		fail(w, 500, err.Error())
		return
	}
	s.S.Audit(user(r), "settings.scan_policy", "", p)
	writeJSON(w, 200, p)
}

func (s *Server) getAllowedPorts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"ports": s.S.GetSetting("allowed_ports")})
}

func (s *Server) putAllowedPorts(w http.ResponseWriter, r *http.Request) {
	var in struct{ Ports string }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	norm := ""
	if strings.TrimSpace(in.Ports) != "" {
		sp, err := ports.Parse(in.Ports)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		norm = sp.NmapArg()
	}
	_ = s.S.SetSetting("allowed_ports", norm)
	s.S.Audit(user(r), "settings.allowed_ports", norm, nil)
	writeJSON(w, 200, map[string]string{"ports": norm})
}

// importSigs: import sygnatur z pliku (MoNet YAML/JSON, nuclei, Wappalyzer, CSV). mode=preview tylko pokazuje wynik.
func (s *Server) importSigs(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		fail(w, 400, "oczekiwano pliku (multipart/form-data)")
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		fail(w, 400, "brak pliku")
		return
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, 32<<20))
	res, err := sig.Convert(data, hdr.Filename)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	existing := map[string]bool{}
	rows, _ := s.S.DB.Query(`SELECT sid FROM signatures`)
	for rows != nil && rows.Next() {
		var id string
		_ = rows.Scan(&id)
		existing[id] = true
	}
	if rows != nil {
		rows.Close()
	}
	type item struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Category string `json:"category"`
		Matchers int    `json:"matchers"`
		Paths    int    `json:"paths"`
		Conflict bool   `json:"conflict"`
		Status   string `json:"status"`
	}
	items := []item{}
	mode, onConflict := r.FormValue("mode"), r.FormValue("on_conflict")
	added, updated, skipped := 0, 0, 0
	for _, sg := range res.Signatures {
		it := item{ID: sg.ID, Name: sg.Name, Category: sg.Category, Matchers: len(sg.Matchers), Conflict: existing[sg.ID]}
		for _, m := range sg.Matchers {
			if m.Type == "path" {
				it.Paths++
			}
		}
		if mode == "import" {
			body, _ := yaml.Marshal(sg)
			switch {
			case it.Conflict && onConflict == "overwrite":
				_, err = s.S.DB.Exec(`UPDATE signatures SET name=?, category=?, body=?, enabled=1, updated_at=?, created_by=? WHERE sid=?`, sg.Name, sg.Category, string(body), store.Now(), user(r), sg.ID)
				it.Status, updated = "nadpisana", updated+1
			case it.Conflict:
				it.Status, skipped = "pominięta (istnieje)", skipped+1
			default:
				_, err = s.S.DB.Exec(`INSERT INTO signatures(sid,name,category,enabled,builtin,body,created_by,updated_at) VALUES(?,?,?,1,0,?,?,?)`,
					sg.ID, sg.Name, sg.Category, string(body), user(r), store.Now())
				it.Status, added = "dodana", added+1
			}
			if err != nil {
				it.Status = "błąd: " + err.Error()
			}
		}
		items = append(items, it)
	}
	if mode == "import" {
		_ = ReloadSignatures(s.S, s.Sigs)
		s.S.Audit(user(r), "signatures.import", hdr.Filename, map[string]any{"format": res.Format, "added": added, "updated": updated, "skipped": skipped})
	}
	writeJSON(w, 200, map[string]any{"format": res.Format, "items": items, "warnings": res.Warnings, "unsupported": res.Skipped,
		"added": added, "updated": updated, "skipped": skipped})
}

func (s *Server) exportSigs(w http.ResponseWriter, r *http.Request) {
	list := s.Sigs.All()
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Disposition", `attachment; filename="asi-signatures.json"`)
		writeJSON(w, 200, map[string]any{"signatures": list})
		return
	}
	b, _ := yaml.Marshal(list)
	w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="asi-signatures.yaml"`)
	_, _ = w.Write(b)
}

// retryDojo: ponawia nieudaną wysyłkę z historii (ten sam skan, tryb i tytuł testu).
func (s *Server) retryDojo(w http.ResponseWriter, r *http.Request) {
	var scanID int64
	var mode, title, perr string
	if err := s.S.DB.QueryRow(`SELECT scan_id,mode,test_title,error FROM dojo_pushes WHERE id=?`, idParam(r)).Scan(&scanID, &mode, &title, &perr); err != nil {
		fail(w, 404, "brak wpisu w historii")
		return
	}
	// ponowienie starego eksportu po nowszym udanym cofnęłoby stan DefectDojo (reimport zamyka findingi spoza wysyłki)
	var newer int
	_ = s.S.DB.QueryRow(`SELECT COUNT(*) FROM dojo_pushes WHERE id>? AND test_title=? AND error=''`, idParam(r), title).Scan(&newer)
	if newer > 0 && strings.HasPrefix(mode, "reimport") {
		fail(w, 409, "po tej wysyłce był już udany eksport do tego samego testu; ponowienie cofnęłoby stan DefectDojo")
		return
	}
	minInt := 20
	if scanID > 0 {
		var cfgID int64
		_ = s.S.DB.QueryRow(`SELECT COALESCE(config_id,0) FROM scans WHERE id=?`, scanID).Scan(&cfgID)
		if c, err := scan.GetConfig(s.S.DB, cfgID); err == nil && strings.Contains(mode, "auto") {
			minInt = c.DojoMinInterest
		}
	}
	obs, name, err := s.dojoObs(scanID, nil, minInt)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	var res map[string]any
	if strings.HasPrefix(mode, "reimport") {
		res, err = dojo.Reimport(ctx, s.dojoSettings(), obs, title)
	} else {
		title = name
		res, err = dojo.Push(ctx, s.dojoSettings(), obs, name)
	}
	dojo.Record(s.S.DB, user(r), scanID, mode+" (ponowienie)", title, len(obs), res, err)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.S.Audit(user(r), "dojo.retry", strconv.FormatInt(scanID, 10), map[string]int{"findings": len(obs)})
	writeJSON(w, 200, map[string]any{"sent": len(obs)})
}

// dojoHistory: historia wysyłek do DefectDojo z liczbami zmian po stronie DefectDojo.
func (s *Server) dojoHistory(w http.ResponseWriter, r *http.Request) {
	rows, err := s.S.DB.Query(`SELECT id,ts,username,scan_id,mode,test_title,test_id,sent,created,closed,reactivated,untouched,total_after,error FROM dojo_pushes ORDER BY id DESC LIMIT 100`)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, scan int64
		var ts, u, mode, title, e string
		var tid, sent, cr, cl, re, un, ta int
		_ = rows.Scan(&id, &ts, &u, &scan, &mode, &title, &tid, &sent, &cr, &cl, &re, &un, &ta, &e)
		out = append(out, map[string]any{"id": id, "ts": ts, "user": u, "scan_id": scan, "mode": mode, "test_title": title, "test_id": tid, "sent": sent,
			"created": cr, "closed": cl, "reactivated": re, "untouched": un, "total_after": ta, "error": e})
	}
	writeJSON(w, 200, out)
}
