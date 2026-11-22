package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/asi-agh/asi/internal/httpprobe"
	"github.com/asi-agh/asi/internal/nmap"
	"github.com/asi-agh/asi/internal/ports"
	"github.com/asi-agh/asi/internal/store"
)

// Doskanowanie w ciągu dnia: poza głównym oknem (np. 22–06) skaner co N minut sprawdza małą paczkę końcówek,
// których nie udało się osiągnąć w ostatnim skanie (stan missing/unreachable/unstable), z niskim tempem.
// Wyniki trafiają od razu do bazy urządzeń, a pomiary zasilają histogram pory dnia (np. host aktywny 8–16).

var retryMu sync.Map // config_id → *sync.Mutex (jedna paczka naraz na konfigurację)

// RetryCandidates: końcówki z ostatniego głównego skanu konfiguracji, które nie odpowiedziały.
// Kolejność: najpierw adresy jeszcze NIEsprawdzone przez doskaner po tym skanie (kolejność adresów), potem kolejne
// okrążenia (od sprawdzanych najdawniej).
func (e *Engine) RetryCandidates(cfgID int64, limit int) ([]string, error) {
	var mainID int64
	var mainEnd string
	_ = e.S.DB.QueryRow(`SELECT id, COALESCE(NULLIF(finished_at,''), created_at) FROM scans WHERE config_id=? AND source='scan'
ORDER BY id DESC LIMIT 1`, cfgID).Scan(&mainID, &mainEnd)
	if mainID == 0 {
		return nil, nil
	}
	rows, err := e.S.DB.Query(`SELECT h.ip FROM hosts h
WHERE h.state IN ('missing','unreachable','unstable')
  AND h.ip IN (SELECT sh.ip FROM scan_hosts sh WHERE sh.alive=0 AND sh.scan_id=?)
ORDER BY CASE WHEN COALESCE(h.last_checked,'') > ? THEN 1 ELSE 0 END, COALESCE(h.last_checked,''), h.ip LIMIT ?`, mainID, mainEnd, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		_ = rows.Scan(&ip)
		out = append(out, ip)
	}
	return out, nil
}

// RetryProgress: ile nieosiągniętych końcówek doskaner sprawdził już po ostatnim głównym skanie.
func (e *Engine) RetryProgress(cfgID int64) (done, total int) {
	var mainID int64
	var mainEnd string
	_ = e.S.DB.QueryRow(`SELECT id, COALESCE(NULLIF(finished_at,''), created_at) FROM scans WHERE config_id=? AND source='scan'
ORDER BY id DESC LIMIT 1`, cfgID).Scan(&mainID, &mainEnd)
	_ = e.S.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN COALESCE(h.last_checked,'') > ? THEN 1 ELSE 0 END),0) FROM hosts h
WHERE h.state IN ('missing','unreachable','unstable') AND h.ip IN (SELECT ip FROM scan_hosts WHERE alive=0 AND scan_id=?)`, mainEnd, mainID).Scan(&total, &done)
	return
}

// retryScanID: jeden skan typu „retry” na konfigurację i dzień (zbiera wszystkie paczki doskanowania).
func (e *Engine) retryScanID(cfg *Config) (int64, error) {
	day := time.Now().Format("2006-01-02")
	name := fmt.Sprintf("Doskanowanie · %s · %s", cfg.Name, day)
	var id int64
	err := e.S.DB.QueryRow(`SELECT id FROM scans WHERE config_id=? AND source='retry' AND name=?`, cfg.ID, name).Scan(&id)
	if err == nil {
		return id, nil
	}
	res, err := e.S.DB.Exec(`INSERT INTO scans(config_id,name,status,ports,config_snapshot,created_at,started_at,triggered_by,source)
VALUES(?,?,?,?,?,?,?,'doskanowanie','retry')`, cfg.ID, name, "completed", cfg.Ports, store.ToJSON(cfg), store.Now(), store.Now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

type RetryResult struct {
	ScanID  int64    `json:"scan_id"`
	Checked int      `json:"checked"`
	Found   []string `json:"found"`
}

// RetryBatch: doskanowanie paczki adresów z niskim tempem (1 worker, 1/10 limitu konfiguracji).
func (e *Engine) RetryBatch(ctx context.Context, cfg *Config, ips []string) (*RetryResult, error) {
	if len(ips) == 0 {
		return &RetryResult{}, nil
	}
	m, _ := retryMu.LoadOrStore(cfg.ID, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	if !mu.TryLock() {
		return nil, errors.New("doskanowanie tej konfiguracji już trwa")
	}
	defer mu.Unlock()
	id, err := e.retryScanID(cfg)
	if err != nil {
		return nil, err
	}
	sp, _ := ports.Parse(cfg.Ports)
	sc := &scanCtx{id: id, cfg: *cfg, sp: sp, hostnames: map[string][]string{}, scope: map[string]bool{}, known: map[string]string{}, explicit: map[string]bool{}}
	for _, ip := range ips {
		sc.scope[ip] = true
		sc.known[ip] = "missing" // każdy adres z paczki dostaje ponowny pomiar z większą liczbą sond
	}
	sc.cfg.RetryUnstable = true
	sc.prober = httpprobe.New(httpprobe.NewLimiter(max(1, cfg.HTTPRPS/4)), 8*time.Second, func(h string) bool { return sc.scope[h] }, nil)
	sc.opts = nmap.Options{Binary: e.NmapBin, Privileged: e.Privileged, MaxRate: max(10, cfg.Rate/10), Retries: cfg.Retries,
		HostTimeout: time.Duration(cfg.HostTimeoutSec) * time.Second, DiscoveryPorts: cfg.DiscoveryPorts, NoARP: e.NoARP, Intensity: cfg.VersionIntens}
	hosts, obs, err := e.scanIPs(ctx, sc, ips)
	if err != nil {
		return nil, err
	}
	res := &RetryResult{ScanID: id, Checked: len(ips)}
	tx, err := e.S.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, ip := range ips {
		h := hosts[ip]
		alive := h != nil && h.alive
		reason, hn := "retry:no-response", ""
		if alive {
			reason, hn = "retry:"+h.reason, h.hostname
			res.Found = append(res.Found, ip)
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO scan_hosts(scan_id,ip,alive,hostname,reason,retried) VALUES(?,?,?,?,?,1)`, id, ip, b2i(alive), hn, reason); err != nil {
			return nil, err
		}
	}
	ApplyOverrides(e.S.DB, obs)
	for _, o := range obs {
		if err := InsertObservation(tx, e.S, id, o); err != nil {
			return nil, err
		}
	}
	if err := updateInventory(tx, id, ips, hosts, obs, sp, cfg.GoneAfter, time.Now().Hour(), store.Now(), true); err != nil {
		return nil, err
	}
	var live, svc, total int
	_ = tx.QueryRow(`SELECT COUNT(DISTINCT ip) FROM scan_hosts WHERE scan_id=? AND alive=1`, id).Scan(&live)
	_ = tx.QueryRow(`SELECT COUNT(*) FROM observations WHERE scan_id=?`, id).Scan(&svc)
	_ = tx.QueryRow(`SELECT COUNT(*) FROM scan_hosts WHERE scan_id=?`, id).Scan(&total)
	if _, err := tx.Exec(`UPDATE scans SET live_hosts=?, open_services=?, total_ips=?, done_ips=?, finished_at=?, windows=windows+1 WHERE id=?`,
		live, svc, total, total, store.Now(), id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	e.logf("doskanowanie %q: sprawdzono %d, odpowiedziało %d %s", cfg.Name, len(ips), len(res.Found), strings.Join(res.Found, ","))
	return res, nil
}

// MarshalRetry: pomocnicze do API.
func MarshalRetry(r *RetryResult) string { b, _ := json.Marshal(r); return string(b) }
