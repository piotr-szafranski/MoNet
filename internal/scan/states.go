package scan

import (
	"database/sql"
	"strconv"
	"encoding/json"

	"github.com/asi-agh/asi/internal/ports"
	"github.com/asi-agh/asi/internal/store"
)

const historyLen = 20

// HostState: active | missing (nie odpowiedział, ale jeszcze nie „zniknął”) | unstable | gone.
func computeState(history string, missStreak, goneAfter int) string {
	if missStreak >= goneAfter {
		return "gone"
	}
	h := history
	if len(h) > 10 {
		h = h[len(h)-10:]
	}
	flips := 0
	for i := 1; i < len(h); i++ {
		if h[i] != h[i-1] {
			flips++
		}
	}
	if flips >= 2 {
		return "unstable"
	}
	if missStreak > 0 {
		return "missing"
	}
	return "active"
}

func pushHistory(h string, seen bool) string {
	c := "0"
	if seen {
		c = "1"
	}
	h += c
	if len(h) > historyLen {
		h = h[len(h)-historyLen:]
	}
	return h
}

func bump(arr string, hour int) string {
	var a []int
	_ = json.Unmarshal([]byte(arr), &a)
	if len(a) != 24 {
		a = make([]int, 24)
	}
	if hour >= 0 && hour < 24 {
		a[hour]++
	}
	return store.ToJSON(a)
}

// Finalize: zamknięcie skanu. Inwentarz (hosty, usługi, stany) jest aktualizowany na bieżąco po każdej podgrupie
// (updateInventory w saveJob), więc tu zostaje tylko podsumowanie.
func (e *Engine) Finalize(id int64) error {
	var live, svcN int
	_ = e.S.DB.QueryRow(`SELECT COUNT(*) FROM scan_hosts WHERE scan_id=? AND alive=1`, id).Scan(&live)
	_ = e.S.DB.QueryRow(`SELECT COUNT(*) FROM observations WHERE scan_id=?`, id).Scan(&svcN)
	_, err := e.S.DB.Exec(`UPDATE scans SET status='completed', finished_at=?, live_hosts=?, open_services=?, done_ips=total_ips WHERE id=?`,
		store.Now(), live, svcN, id)
	return err
}

type txq interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
}

// updateInventory: aktualizacja bazy urządzeń dla adresów jednej podgrupy (albo paczki doskanowania).
//   - host odpowiedział: last_seen, seria braków = 0, historia „1”, histogram godzin,
//   - znany host nie odpowiedział (także po ponownym pomiarze): seria braków +1, historia „0”, stan missing/gone,
//   - cel podany jako pojedynczy adres, który nigdy nie odpowiedział: stan „unreachable” (do doskanowania),
//   - retry=true (doskanowanie w dzień): brak odpowiedzi nie zwiększa serii braków, liczy się tylko do histogramu.
func updateInventory(tx txq, scanID int64, scope []string, hosts map[string]*hostRes, obs []*Observation, sp ports.Spec,
	goneAfter, hour int, now string, retry bool) error {
	type hrow struct {
		history, hs, hsc, state string
		miss, seen               int
	}
	existing := map[string]*hrow{}
	rows, err := tx.Query(`SELECT ip,history,hours_seen,hours_scanned,miss_streak,seen_count,state FROM hosts
WHERE ip IN (SELECT value FROM json_each(?))`, store.ToJSON(scope))
	if err != nil {
		return err
	}
	for rows.Next() {
		var ip string
		r := &hrow{}
		_ = rows.Scan(&ip, &r.history, &r.hs, &r.hsc, &r.miss, &r.seen, &r.state)
		existing[ip] = r
	}
	rows.Close()

	alive := map[string]bool{}
	for _, ip := range scope {
		h := hosts[ip]
		r := existing[ip]
		switch {
		case h != nil && h.alive:
			alive[ip] = true
			if r == nil {
				_, err = tx.Exec(`INSERT INTO hosts(ip,first_seen,last_seen,seen_count,scan_count,miss_streak,state,history,hours_seen,hours_scanned,hostname,last_scan_id,state_changed,last_checked)
VALUES(?,?,?,1,1,0,'active',?,?,?,?,?,?,?)`, ip, now, now, pushHistory("", true), bump("", hour), bump("", hour), h.hostname, scanID, now, now)
			} else {
				hist := pushHistory(r.history, true)
				st := computeState(hist, 0, goneAfter)
				_, err = tx.Exec(`UPDATE hosts SET first_seen=CASE WHEN first_seen IS NULL OR first_seen='' THEN ? ELSE first_seen END, last_seen=?,
seen_count=seen_count+1, scan_count=scan_count+1, miss_streak=0, history=?, hours_seen=?, hours_scanned=?,
hostname=CASE WHEN ?!='' THEN ? ELSE hostname END, last_scan_id=?, state=?, last_checked=?,
state_changed=CASE WHEN state!=? THEN ? ELSE state_changed END WHERE ip=?`,
					now, now, hist, bump(r.hs, hour), bump(r.hsc, hour), h.hostname, h.hostname, scanID, st, now, st, now, ip)
			}
		case r != nil && retry:
			_, err = tx.Exec(`UPDATE hosts SET hours_scanned=?, last_checked=? WHERE ip=?`, bump(r.hsc, hour), now, ip)
		case r != nil:
			hist := pushHistory(r.history, false)
			st := computeState(hist, r.miss+1, goneAfter)
			if r.seen == 0 {
				st = "unreachable"
			}
			_, err = tx.Exec(`UPDATE hosts SET scan_count=scan_count+1, miss_streak=miss_streak+1, history=?, hours_scanned=?, last_scan_id=?, state=?,
last_checked=?, state_changed=CASE WHEN state!=? THEN ? ELSE state_changed END WHERE ip=?`, hist, bump(r.hsc, hour), scanID, st, now, st, now, ip)
		case h != nil && !retry:
			// cel wskazany wprost, nigdy nie odpowiedział: rejestrujemy jako nieosiągalny
			_, err = tx.Exec(`INSERT INTO hosts(ip,first_seen,last_seen,seen_count,scan_count,miss_streak,state,history,hours_seen,hours_scanned,last_scan_id,state_changed,last_checked)
VALUES(?,'','',0,1,1,'unreachable',?,?,?,?,?,?)`, ip, pushHistory("", false), bump("", -1), bump("", hour), scanID, now, now)
		}
		if err != nil {
			return err
		}
	}

	// usługi: oceniane tylko na portach z listy skanu (inaczej fałszywe „zniknięcia”)
	open := map[string]int64{}
	for _, o := range obs {
		open[o.IP+"|"+itoa(o.Port)+"|"+o.Proto] = o.ID
	}
	type srow struct {
		ip, proto, history string
		port, miss         int
	}
	var svcs []srow
	rows, err = tx.Query(`SELECT ip,port,proto,history,miss_streak FROM services WHERE ip IN (SELECT value FROM json_each(?))`, store.ToJSON(scope))
	if err != nil {
		return err
	}
	for rows.Next() {
		var r srow
		_ = rows.Scan(&r.ip, &r.port, &r.proto, &r.history, &r.miss)
		if sp.Contains(r.proto, r.port) {
			svcs = append(svcs, r)
		}
	}
	rows.Close()
	seen := map[string]bool{}
	for _, r := range svcs {
		k := r.ip + "|" + itoa(r.port) + "|" + r.proto
		seen[k] = true
		if oid, ok := open[k]; ok {
			hist := pushHistory(r.history, true)
			_, err = tx.Exec(`UPDATE services SET last_seen=?, miss_streak=0, history=?, state=?, last_obs_id=? WHERE ip=? AND port=? AND proto=?`,
				now, hist, computeState(hist, 0, goneAfter), oid, r.ip, r.port, r.proto)
		} else if retry && !alive[r.ip] {
			continue // doskanowanie: host nadal niedostępny, usług nie oceniamy
		} else {
			hist := pushHistory(r.history, false)
			_, err = tx.Exec(`UPDATE services SET miss_streak=miss_streak+1, history=?, state=? WHERE ip=? AND port=? AND proto=?`,
				hist, computeState(hist, r.miss+1, goneAfter), r.ip, r.port, r.proto)
		}
		if err != nil {
			return err
		}
	}
	for _, o := range obs {
		k := o.IP + "|" + itoa(o.Port) + "|" + o.Proto
		if seen[k] {
			continue
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO services(ip,port,proto,first_seen,last_seen,miss_streak,state,history,last_obs_id) VALUES(?,?,?,?,?,0,'active',?,?)`,
			o.IP, o.Port, o.Proto, now, now, pushHistory("", true), o.ID); err != nil {
			return err
		}
	}
	return nil
}

func itoa(i int) string { return strconv.Itoa(i) }

// ---- odczyt obserwacji (z odszyfrowaniem) ----

const ObsCols = obsCols

// ObsColsPrefixed: kolumny obserwacji z aliasem tabeli (do złączeń).
func ObsColsPrefixed(a string) string {
	return a + ".id," + a + ".scan_id," + a + ".ip," + a + ".port," + a + ".proto," + a + ".state," + a + ".service," + a + ".product," + a + ".version," +
		a + ".tls," + a + ".http_status," + a + ".techs," + a + ".flags," + a + ".interest," + a + ".data_enc," + a + ".fingerprint," + a + ".edited," +
		a + ".edited_by,COALESCE(" + a + ".seen_at,''),COALESCE(" + a + ".rules,'[]'),COALESCE(" + a + ".response_ms,0)"
}

const obsCols = `id,scan_id,ip,port,proto,state,service,product,version,tls,http_status,techs,flags,interest,data_enc,fingerprint,edited,edited_by,COALESCE(seen_at,''),COALESCE(rules,'[]'),COALESCE(response_ms,0)`

func ScanObs(s *store.Store, row interface{ Scan(...any) error }, decrypt bool) (*Observation, error) {
	o := &Observation{}
	var tls, edited int
	var techs, flags, data, rl string
	if err := row.Scan(&o.ID, &o.ScanID, &o.IP, &o.Port, &o.Proto, &o.State, &o.Service, &o.Product, &o.Version, &tls, &o.HTTPStatus,
		&techs, &flags, &o.Interest, &data, &o.Fingerprint, &edited, &o.EditedBy, &o.SeenAt, &rl, &o.ResponseMs); err != nil {
		return nil, err
	}
	o.TLS, o.Edited = tls == 1, edited == 1
	_ = json.Unmarshal([]byte(techs), &o.Techs)
	_ = json.Unmarshal([]byte(flags), &o.Flags)
	_ = json.Unmarshal([]byte(rl), &o.Rules)
	if o.Rules == nil {
		o.Rules = []string{}
	}
	if o.Techs == nil {
		o.Techs = []Tech{}
	}
	if o.Flags == nil {
		o.Flags = []string{}
	}
	if decrypt {
		_ = json.Unmarshal([]byte(s.Box.MustOpen(data)), &o.Data)
	}
	return o, nil
}

// ScanObsPrefixed: jak ScanObs, ale z dodatkowymi kolumnami na początku wiersza.
func ScanObsPrefixed(s *store.Store, row interface{ Scan(...any) error }, decrypt bool, pre ...any) (*Observation, error) {
	o := &Observation{}
	var tls, edited int
	var techs, flags, data, rl string
	dst := append(pre, &o.ID, &o.ScanID, &o.IP, &o.Port, &o.Proto, &o.State, &o.Service, &o.Product, &o.Version, &tls, &o.HTTPStatus,
		&techs, &flags, &o.Interest, &data, &o.Fingerprint, &edited, &o.EditedBy, &o.SeenAt, &rl, &o.ResponseMs)
	if err := row.Scan(dst...); err != nil {
		return nil, err
	}
	o.TLS, o.Edited = tls == 1, edited == 1
	_ = json.Unmarshal([]byte(techs), &o.Techs)
	_ = json.Unmarshal([]byte(flags), &o.Flags)
	_ = json.Unmarshal([]byte(rl), &o.Rules)
	if o.Rules == nil {
		o.Rules = []string{}
	}
	if o.Techs == nil {
		o.Techs = []Tech{}
	}
	if o.Flags == nil {
		o.Flags = []string{}
	}
	if decrypt {
		_ = json.Unmarshal([]byte(s.Box.MustOpen(data)), &o.Data)
	}
	return o, nil
}

func ListObs(s *store.Store, where string, decrypt bool, args ...any) ([]*Observation, error) {
	rows, err := s.DB.Query(`SELECT `+obsCols+` FROM observations `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Observation
	for rows.Next() {
		o, err := ScanObs(s, rows, decrypt)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

func GetObs(s *store.Store, id int64) (*Observation, error) {
	return ScanObs(s, s.DB.QueryRow(`SELECT `+obsCols+` FROM observations WHERE id=?`, id), true)
}

var _ = sql.ErrNoRows
