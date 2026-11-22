// Package scan: silnik skanu discovery. Planer dzieli adresy na podgrupy dopasowane do zmierzonego tempa,
// workery uruchamiają nmap (discovery → usługi) i sondę HTTP, wyniki trafiają do bazy (pola wrażliwe szyfrowane).
// Skan zatrzymuje się po końcu okna czasowego i wznawia od miejsca przerwania w kolejnym oknie.
package scan

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/asi-agh/asi/internal/httpprobe"
	"github.com/asi-agh/asi/internal/nmap"
	"github.com/asi-agh/asi/internal/ports"
	"github.com/asi-agh/asi/internal/sig"
	"github.com/asi-agh/asi/internal/store"
	"github.com/asi-agh/asi/internal/targets"
)

const BlockSize = 64

type Banner struct {
	Product   string   `json:"product,omitempty"`
	Version   string   `json:"version,omitempty"`
	ExtraInfo string   `json:"extrainfo,omitempty"`
	Tunnel    string   `json:"tunnel,omitempty"`
	Method    string   `json:"method,omitempty"`
	Conf      int      `json:"conf,omitempty"`
	CPE       []string `json:"cpe,omitempty"`
	DevType   string   `json:"devtype,omitempty"`
	OSType    string   `json:"ostype,omitempty"`
}

type ObsData struct {
	Hostname   string            `json:"hostname,omitempty"`
	MAC        string            `json:"mac,omitempty"`
	Vendor     string            `json:"vendor,omitempty"`
	Banner     Banner            `json:"banner"`
	HTTP       *httpprobe.Result `json:"http,omitempty"`
	Detections []sig.Detection   `json:"detections,omitempty"`
	Note       string            `json:"note,omitempty"`
}

// Tech: jawna (niezaszyfrowana) skrócona postać detekcji, do filtrowania i grupowania.
type Tech struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	Version    string `json:"version,omitempty"`
	Confidence int    `json:"confidence"`
	Source     string `json:"source,omitempty"` // puste = sygnatura; "nmap" / "nagłówek Server" = automatycznie z banera
}

type Observation struct {
	ID          int64    `json:"id"`
	ScanID      int64    `json:"scan_id"`
	IP          string   `json:"ip"`
	Port        int      `json:"port"`
	Proto       string   `json:"proto"`
	State       string   `json:"state"`
	Service     string   `json:"service"`
	Product     string   `json:"product"`
	Version     string   `json:"version"`
	TLS         bool     `json:"tls"`
	HTTPStatus  int      `json:"http_status"`
	ResponseMs  int64    `json:"response_ms"` // czas pierwszej odpowiedzi HTTP (bez kolejki limitera)
	Techs       []Tech   `json:"techs"`
	Flags       []string `json:"flags"`
	Interest    int      `json:"interest"`
	Rules       []string `json:"rules"` // dopasowane reguły klasy (pokrycie X z N)
	Fingerprint string   `json:"fingerprint"`
	SeenAt      string   `json:"seen_at"` // kiedy usługa została przeskanowana
	Edited      bool     `json:"edited"`
	EditedBy    string   `json:"edited_by,omitempty"`
	Data        ObsData  `json:"data"`
}

func (o *Observation) Finalize() {
	o.Techs = o.Techs[:0]
	for _, d := range o.Data.Detections {
		o.Techs = append(o.Techs, Tech{ID: d.ID, Name: d.Name, Category: d.Category, Version: d.Version, Confidence: d.Confidence})
	}
	o.addBannerTech()
	if h := o.Data.HTTP; h != nil && h.Error == "" {
		o.HTTPStatus = h.Status
		o.ResponseMs = h.ResponseMs
		o.TLS = h.TLS != nil || h.TLSError != ""
		// nmap tylko zgadł nazwę z tabeli portów, a sonda potwierdziła HTTP: poprawiamy nazwę usługi
		if (o.Data.Banner.Method == "table" || o.Service == "" || o.Service == "unknown" || o.Service == "tcpwrapped") && h.Status > 0 {
			o.Service = h.Scheme
		}
		if h.AltScheme != "" {
			o.TLS = true
			o.Service = "http+https" // port obsługuje oba schematy
		}
		if h.TLSError != "" {
			o.Service = "https" // port TLS (uzgodnienie bez SNI nieudane), a nie zwykłe HTTP
		}
	}
	o.Fingerprint = o.ComputeFingerprint()
}

// safeProcessJob: błąd programu (panic) w jednej podgrupie nie wywraca całej aplikacji: podgrupa jest
// raportowana jako nieudana, a skan idzie dalej.
func (e *Engine) safeProcessJob(ctx context.Context, sc *scanCtx, job []block, worker int) (n int, err error) {
	defer func() {
		if r := recover(); r != nil {
			e.logf("skan: błąd wewnętrzny w podgrupie (worker %d): %v", worker, r)
			err = fmt.Errorf("błąd wewnętrzny: %v", r)
		}
	}()
	return e.processJob(ctx, sc, job, worker)
}

// addBannerTech: technologia z banera usługi (nmap -sV) albo nagłówka Server, gdy żadna sygnatura jej nie nazwała.
// Dzięki temu każdy produkt rozpoznany przez nmapa trafia do technologii, nawet bez dedykowanej sygnatury.
func (o *Observation) addBannerTech() {
	name, ver, src := strings.TrimSpace(o.Product), strings.TrimSpace(o.Version), "nmap"
	if name == "" {
		if h := o.Data.HTTP; h != nil && h.Error == "" {
			if sv := first(h.Headers, "server"); sv != "" {
				name, ver, src = sv, "", "nagłówek Server"
				if i := strings.IndexByte(sv, '/'); i > 0 {
					name, ver = sv[:i], ""
					if f := strings.Fields(sv[i+1:]); len(f) > 0 { // np. „Server: nginx/” bez wersji
						ver = f[0]
					}
				}
			}
		}
	}
	for _, suf := range []string{" web app server", " web server", " httpd", " key-value store", " DB", " smtpd", " ftpd", " sshd"} {
		if strings.HasSuffix(strings.ToLower(name), strings.ToLower(suf)) {
			name = strings.TrimSpace(name[:len(name)-len(suf)])
		}
	}
	name = strings.TrimSpace(name)
	if name == "" || strings.Contains(strings.ToLower(name), "protocol") {
		return
	}
	fields := strings.Fields(name)
	if len(fields) == 0 {
		return
	}
	tok := strings.ToLower(fields[0])
	for _, t := range o.Techs {
		if strings.Contains(strings.ToLower(t.Name), tok) || strings.Contains(strings.ToLower(t.ID), tok) {
			return // sygnatura już to nazwała
		}
	}
	cat := "other"
	if o.Data.HTTP != nil && o.Data.HTTP.Error == "" {
		cat = "server"
	}
	id := "auto-" + strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, strings.ToLower(name))
	o.Techs = append(o.Techs, Tech{ID: id, Name: name, Category: cat, Version: ver, Confidence: 70, Source: src})
}

// LatencyBucket: przedział czasu odpowiedzi. W odcisku i diffie liczy się zmiana przedziału, a nie każda milisekunda.
func LatencyBucket(ms int64) string {
	switch {
	case ms <= 0:
		return ""
	case ms < 300:
		return "szybka (<300 ms)"
	case ms < 1000:
		return "wolniejsza (300–1000 ms)"
	case ms < 3000:
		return "wolna (1–3 s)"
	}
	return "bardzo wolna (≥3 s)"
}

// ComputeFingerprint: skrót cech istotnych dla diffu (zmiana skrótu = usługa zmieniona).
func (o *Observation) ComputeFingerprint() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%s|%s|%d|%s", o.Service, o.Product, o.Version, o.HTTPStatus, LatencyBucket(o.ResponseMs))
	if h := o.Data.HTTP; h != nil && h.Error == "" {
		fmt.Fprintf(&b, "|%s|%s", h.Title, first(h.Headers, "server"))
		if h.TLS != nil {
			b.WriteString("|" + h.TLS.SHA256)
		}
	}
	ids := make([]string, 0, len(o.Techs))
	for _, t := range o.Techs {
		ids = append(ids, t.ID+"@"+t.Version)
	}
	sort.Strings(ids)
	b.WriteString("|" + strings.Join(ids, ","))
	s := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(s[:8])
}

type activeScan struct {
	cancel    context.CancelFunc
	reason    string
	started   time.Time
	mu        sync.Mutex
	rate      float64 // zmierzone IP/s (średnia krocząca)
	chunk     int     // bieżący rozmiar podgrupy (IP)
	inFlight  int
	jobsDone  int
}

type Engine struct {
	S          *store.Store
	Sigs       *sig.Engine
	NmapBin    string
	Privileged bool
	NoARP      bool
	Resolver   targets.Resolver
	Log        *log.Logger
	OnComplete func(scanID int64, cfg *Config) // np. automatyczny eksport do DefectDojo
	mu         sync.Mutex
	active     map[int64]*activeScan
}

func NewEngine(s *store.Store, sigs *sig.Engine, lg *log.Logger) *Engine {
	return &Engine{S: s, Sigs: sigs, Privileged: nmap.IsRoot(), Log: lg, active: map[int64]*activeScan{}}
}

// LiveStats: dane do paska postępu (tempo, rozmiar podgrupy, workery w toku).
type LiveStats struct {
	Running  bool    `json:"running"`
	Rate     float64 `json:"rate_ips"`
	Chunk    int     `json:"chunk_size"`
	InFlight int     `json:"in_flight"`
	Jobs     int     `json:"jobs_done"`
	SegmentMs int64  `json:"segment_ms"` // czas bieżącego okna (od startu/wznowienia)
}

func (e *Engine) Live(id int64) LiveStats {
	e.mu.Lock()
	a := e.active[id]
	e.mu.Unlock()
	if a == nil {
		return LiveStats{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return LiveStats{Running: true, Rate: a.rate, Chunk: a.chunk, InFlight: a.inFlight, Jobs: a.jobsDone, SegmentMs: time.Since(a.started).Milliseconds()}
}

func (e *Engine) IsActive(id int64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.active[id] != nil
}

func (e *Engine) ActiveForConfig(cfgID int64) bool {
	var n int
	_ = e.S.DB.QueryRow(`SELECT COUNT(*) FROM scans WHERE config_id=? AND status IN ('queued','running')`, cfgID).Scan(&n)
	return n > 0
}

// Cancel: zatrzymanie skanu przez użytkownika.
func (e *Engine) Cancel(id int64) bool {
	e.mu.Lock()
	a := e.active[id]
	e.mu.Unlock()
	if a == nil {
		return false
	}
	a.reason = "cancelled"
	a.cancel()
	return true
}

func parseExcludes(s string) []netip.Prefix {
	var out []netip.Prefix
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == ';' }) {
		if p, err := netip.ParsePrefix(tok); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(tok); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// CreateScan: rozwija cele konfiguracji (albo podaną listę) i zapisuje skan z blokami po 64 adresy.
func (e *Engine) CreateScan(ctx context.Context, cfg *Config, explicit []string, user, name string) (int64, error) {
	values := explicit
	if len(values) == 0 {
		rows, err := e.S.DB.Query(`SELECT value,tags FROM targets WHERE enabled=1 ORDER BY id`)
		if err != nil {
			return 0, err
		}
		for rows.Next() {
			var v, tags string
			_ = rows.Scan(&v, &tags)
			if len(cfg.TargetTags) > 0 && !intersects(cfg.TargetTags, store.JSONList(tags)) {
				continue
			}
			values = append(values, v)
		}
		rows.Close()
	}
	if len(values) == 0 {
		return 0, errors.New("brak celów do skanowania (dodaj cele lub zmień tagi konfiguracji)")
	}
	ex, err := targets.Expand(ctx, values, parseExcludes(cfg.Excludes), e.Resolver)
	if err != nil {
		return 0, err
	}
	if len(ex.IPs) == 0 {
		return 0, fmt.Errorf("cele nie dały żadnych adresów IP: %s", strings.Join(ex.Errors, "; "))
	}
	if name == "" {
		name = cfg.Name + " · " + time.Now().Format("2006-01-02 15:04")
	}
	if cfg.AutoAddPorts {
		if added := e.autoAddPorts(cfg); added != "" {
			e.logf("konfiguracja %q: dopisano wykryte porty %s (w ramach portów zatwierdzonych)", cfg.Name, added)
		}
	}
	var explicitIPs []string
	for _, v := range values {
		if norm, kind, err := targets.Classify(v); err == nil && kind == targets.KindIP {
			explicitIPs = append(explicitIPs, norm)
		}
	}
	for ip := range ex.Hostnames {
		explicitIPs = append(explicitIPs, ip)
	}
	tx, err := e.S.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO scans(config_id,name,status,ports,config_snapshot,hostnames,total_ips,created_at,triggered_by,error,explicit)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, cfg.ID, name, "queued", cfg.Ports, store.ToJSON(cfg), store.ToJSON(ex.Hostnames), len(ex.IPs), store.Now(), user,
		strings.Join(ex.Errors, "; "), store.ToJSON(explicitIPs))
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	stmt, err := tx.Prepare(`INSERT INTO scan_blocks(scan_id,idx,ips,size) VALUES(?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	for i := 0; i*BlockSize < len(ex.IPs); i++ {
		part := ex.IPs[i*BlockSize : min((i+1)*BlockSize, len(ex.IPs))]
		ss := make([]string, len(part))
		for j, a := range part {
			ss[j] = a.String()
		}
		if _, err := stmt.Exec(id, i, strings.Join(ss, "\n"), len(ss)); err != nil {
			return 0, err
		}
	}
	stmt.Close()
	return id, tx.Commit()
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if strings.EqualFold(x, y) {
				return true
			}
		}
	}
	return false
}

type block struct {
	id  int64
	ips []string
}

// planner: wydaje workerom podgrupy bloków; rozmiar dopasowuje do zmierzonego tempa (cel: ChunkTargetSec na podgrupę).
type planner struct {
	mu      sync.Mutex
	pending []block
	k       int // bloków na podgrupę
	target  float64
	a       *activeScan
}

func (p *planner) next() []block {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.pending) == 0 {
		return nil
	}
	n := min(p.k, len(p.pending))
	job := p.pending[:n]
	p.pending = p.pending[n:]
	return job
}

func (p *planner) report(ips int, dur time.Duration) {
	if dur <= 0 || ips == 0 {
		return
	}
	rate := float64(ips) / dur.Seconds()
	p.a.mu.Lock()
	if p.a.rate == 0 {
		p.a.rate = rate
	} else {
		p.a.rate = 0.6*p.a.rate + 0.4*rate
	}
	want := p.a.rate * p.target
	p.a.mu.Unlock()
	p.mu.Lock()
	k := int(want/BlockSize + 0.5)
	p.k = max(1, min(k, 64)) // 64–4096 adresów na podgrupę
	p.a.mu.Lock()
	p.a.chunk = p.k * BlockSize
	p.a.mu.Unlock()
	p.mu.Unlock()
}

type scanCtx struct {
	noGeneric bool // polityka: bez ścieżek ogólnych
	id        int64
	cfg       Config
	sp        ports.Spec
	hostnames map[string][]string
	scope     map[string]bool
	known     map[string]string
	explicit  map[string]bool // cele podane wprost (pojedyncze IP / domeny): rejestrujemy je jako nieosiągalne
	prober    *httpprobe.Prober
	opts      nmap.Options
}

// Start uruchamia (albo wznawia) skan w tle. deadline = koniec okna czasowego (zero = bez limitu).
func (e *Engine) Start(id int64, deadline time.Time) error {
	e.mu.Lock()
	if e.active[id] != nil {
		e.mu.Unlock()
		return errors.New("skan już trwa")
	}
	ctx, cancel := context.WithCancel(context.Background())
	if !deadline.IsZero() {
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
	}
	a := &activeScan{cancel: cancel, started: time.Now(), chunk: 4 * BlockSize}
	e.active[id] = a
	e.mu.Unlock()
	_, _ = e.S.DB.Exec(`UPDATE scans SET status='running' WHERE id=?`, id)
	go e.run(ctx, id, a)
	return nil
}

func (e *Engine) logf(f string, v ...any) {
	if e.Log != nil {
		e.Log.Printf(f, v...)
	}
}

func (e *Engine) run(ctx context.Context, id int64, a *activeScan) {
	defer func() {
		a.cancel()
		e.mu.Lock()
		delete(e.active, id)
		e.mu.Unlock()
	}()
	fail := func(err error) {
		e.logf("skan %d: błąd: %v", id, err)
		_, _ = e.S.DB.Exec(`UPDATE scans SET status='failed', error=? WHERE id=?`, err.Error(), id)
	}
	sc, pending, err := e.prepare(id)
	if err != nil {
		fail(err)
		return
	}
	_, _ = e.S.DB.Exec(`UPDATE scans SET status='running', started_at=CASE WHEN started_at='' THEN ? ELSE started_at END, windows=windows+1 WHERE id=?`, store.Now(), id)
	e.logf("skan %d: start, %d bloków do zrobienia, %d workerów", id, len(pending), sc.cfg.Workers)

	pl := &planner{pending: pending, k: 4, target: float64(sc.cfg.ChunkTargetSec), a: a}
	segStart := time.Now()
	var baseElapsed int64
	_ = e.S.DB.QueryRow(`SELECT elapsed_ms FROM scans WHERE id=?`, id).Scan(&baseElapsed)
	// czas trwania zapisywany co 10 s: restart serwera w trakcie okna nie gubi zmierzonego czasu
	tickDone := make(chan struct{})
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-tickDone:
				return
			case <-t.C:
				_, _ = e.S.DB.Exec(`UPDATE scans SET elapsed_ms=? WHERE id=?`, baseElapsed+time.Since(segStart).Milliseconds(), id)
			}
		}
	}()
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	for w := 0; w < sc.cfg.Workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for ctx.Err() == nil {
				job := pl.next()
				if job == nil {
					return
				}
				a.mu.Lock()
				a.inFlight++
				a.mu.Unlock()
				t0 := time.Now()
				n, err := e.safeProcessJob(ctx, sc, job, worker)
				a.mu.Lock()
				a.inFlight--
				a.jobsDone++
				a.mu.Unlock()
				if err != nil {
					if ctx.Err() == nil {
						errMu.Lock()
						if firstErr == nil {
							firstErr = err
						}
						errMu.Unlock()
						e.logf("skan %d: podgrupa nieudana: %v", id, err)
						e.resetBlocks(job, "pending")
					}
					continue
				}
				pl.report(n, time.Since(t0))
			}
		}(w)
	}
	wg.Wait()
	close(tickDone)
	_, _ = e.S.DB.Exec(`UPDATE scans SET elapsed_ms=? WHERE id=?`, baseElapsed+time.Since(segStart).Milliseconds(), id)
	_, _ = e.S.DB.Exec(`UPDATE scan_blocks SET status='pending', job=0 WHERE scan_id=? AND status='running'`, id)

	if ctx.Err() != nil {
		status := "paused"
		if a.reason == "cancelled" {
			status = "cancelled"
		}
		e.logf("skan %d: zatrzymany (%s)", id, status)
		_, _ = e.S.DB.Exec(`UPDATE scans SET status=? WHERE id=?`, status, id)
		return
	}
	var left int
	_ = e.S.DB.QueryRow(`SELECT COUNT(*) FROM scan_blocks WHERE scan_id=? AND status!='done'`, id).Scan(&left)
	if left > 0 {
		msg := fmt.Sprintf("%d bloków nieukończonych", left)
		if firstErr != nil {
			msg += ": " + firstErr.Error()
		}
		_, _ = e.S.DB.Exec(`UPDATE scans SET status='paused', error=? WHERE id=?`, msg, id)
		return
	}
	if err := e.Finalize(id); err != nil {
		fail(err)
		return
	}
	e.logf("skan %d: zakończony", id)
	if e.OnComplete != nil {
		cfg := sc.cfg
		go e.OnComplete(id, &cfg)
	}
}

func (e *Engine) prepare(id int64) (*scanCtx, []block, error) {
	var snap, hn, portsStr, expl string
	if err := e.S.DB.QueryRow(`SELECT config_snapshot,hostnames,ports,COALESCE(explicit,'[]') FROM scans WHERE id=?`, id).Scan(&snap, &hn, &portsStr, &expl); err != nil {
		return nil, nil, err
	}
	sc := &scanCtx{id: id, hostnames: map[string][]string{}, scope: map[string]bool{}, known: map[string]string{}, explicit: map[string]bool{}}
	for _, ip := range store.JSONList(expl) {
		sc.explicit[ip] = true
	}
	if err := json.Unmarshal([]byte(snap), &sc.cfg); err != nil {
		return nil, nil, err
	}
	_ = sc.cfg.Normalize()
	_ = json.Unmarshal([]byte(hn), &sc.hostnames)
	sp, err := ports.Parse(portsStr)
	if err != nil {
		return nil, nil, err
	}
	sc.sp = sp
	_, _ = e.S.DB.Exec(`UPDATE scan_blocks SET status='pending' WHERE scan_id=? AND status='running'`, id)
	rows, err := e.S.DB.Query(`SELECT id,ips,status FROM scan_blocks WHERE scan_id=? ORDER BY idx`, id)
	if err != nil {
		return nil, nil, err
	}
	var pending []block
	for rows.Next() {
		var b block
		var ips, st string
		_ = rows.Scan(&b.id, &ips, &st)
		b.ips = strings.Split(ips, "\n")
		for _, ip := range b.ips {
			sc.scope[ip] = true
		}
		if st != "done" {
			pending = append(pending, b)
		}
	}
	rows.Close()
	// polityka administratora: twarde limity tempa i dozwolone sieci (sprawdzane przy każdym starcie i wznowieniu)
	pol := LoadPolicy(e.S)
	if ch := pol.Clamp(&sc.cfg); len(ch) > 0 {
		e.logf("skan %d: limity administratora: %s", id, strings.Join(ch, ", "))
	}
	scope := make([]string, 0, len(sc.scope))
	for ip := range sc.scope {
		scope = append(scope, ip)
	}
	if err := pol.CheckIPs(scope); err != nil {
		return nil, nil, err
	}
	sc.noGeneric = pol.NoGenericPaths
	hr, err := e.S.DB.Query(`SELECT ip,state FROM hosts WHERE state!='gone'`)
	if err == nil {
		for hr.Next() {
			var ip, st string
			_ = hr.Scan(&ip, &st)
			if sc.scope[ip] {
				sc.known[ip] = st
			}
		}
		hr.Close()
	}
	// priorytet: najpierw bloki z końcówkami, których nie udało się osiągnąć w poprzednich skanach
	isMissing := func(b block) bool {
		for _, ip := range b.ips {
			if st := sc.known[ip]; st == "missing" || st == "unreachable" || st == "unstable" {
				return true
			}
		}
		return false
	}
	sort.SliceStable(pending, func(i, j int) bool { return isMissing(pending[i]) && !isMissing(pending[j]) })
	hostSet := map[string]bool{}
	for _, names := range sc.hostnames {
		for _, n := range names {
			hostSet[strings.ToLower(n)] = true
		}
	}
	inScope := func(h string) bool { return sc.scope[h] || hostSet[strings.ToLower(h)] }
	sc.prober = httpprobe.New(httpprobe.NewLimiter(sc.cfg.HTTPRPS), 8*time.Second, inScope, nil)
	sc.opts = nmap.Options{Binary: e.NmapBin, Privileged: e.Privileged, MaxRate: max(10, sc.cfg.Rate/sc.cfg.Workers),
		Retries: sc.cfg.Retries, HostTimeout: time.Duration(sc.cfg.HostTimeoutSec) * time.Second,
		DiscoveryPorts: sc.cfg.DiscoveryPorts, NoARP: e.NoARP, Intensity: sc.cfg.VersionIntens}
	return sc, pending, nil
}

func (e *Engine) resetBlocks(job []block, status string) {
	for _, b := range job {
		_, _ = e.S.DB.Exec(`UPDATE scan_blocks SET status=?, job=0 WHERE id=?`, status, b.id)
	}
}

type hostRes struct {
	ip, hostname, reason, mac, vendor string
	alive, retried                    bool
}

func (e *Engine) processJob(ctx context.Context, sc *scanCtx, job []block, worker int) (int, error) {
	t0 := time.Now()
	var ips []string
	for _, b := range job {
		ips = append(ips, b.ips...)
		_, _ = e.S.DB.Exec(`UPDATE scan_blocks SET status='running', job=? WHERE id=?`, worker+1, b.id)
	}
	hosts, obs, err := e.scanIPs(ctx, sc, ips)
	if err != nil {
		return 0, err
	}
	for _, ip := range ips {
		if hosts[ip] == nil && sc.explicit[ip] {
			hosts[ip] = &hostRes{ip: ip, alive: false, reason: "no-response"}
		}
	}
	if err := e.saveJob(sc, job, ips, hosts, obs, len(ips), worker, time.Since(t0)); err != nil {
		return 0, err
	}
	return len(ips), nil
}

// scanIPs: discovery → ponowny pomiar → usługi → HTTP → sygnatury dla listy adresów (bez zapisu).
func (e *Engine) scanIPs(ctx context.Context, sc *scanCtx, ips []string) (map[string]*hostRes, []*Observation, error) {
	hosts := map[string]*hostRes{}
	run, _, err := nmap.Discovery(ctx, sc.opts, ips, false)
	if err != nil {
		return nil, nil, err
	}
	for _, h := range run.Hosts {
		if h.Status.State == "up" && sc.scope[h.IP()] {
			mac, vendor := h.MAC()
			hosts[h.IP()] = &hostRes{ip: h.IP(), alive: true, reason: h.Status.Reason, hostname: h.Hostname(), mac: mac, vendor: vendor}
		}
	}
	// ponowny pomiar: hosty wcześniej aktywne, które teraz nie odpowiedziały (hosty niestabilne)
	if sc.cfg.RetryUnstable {
		var retry []string
		for _, ip := range ips {
			if hosts[ip] == nil && sc.known[ip] != "" {
				retry = append(retry, ip)
			}
		}
		if len(retry) > 0 {
			r2, _, err := nmap.Discovery(ctx, sc.opts, retry, true)
			if err != nil {
				return nil, nil, err
			}
			up := map[string]bool{}
			for _, h := range r2.Hosts {
				if h.Status.State == "up" {
					up[h.IP()] = true
					hosts[h.IP()] = &hostRes{ip: h.IP(), alive: true, retried: true, reason: "retry:" + h.Status.Reason, hostname: h.Hostname()}
				}
			}
			for _, ip := range retry {
				if !up[ip] {
					hosts[ip] = &hostRes{ip: ip, alive: false, retried: true, reason: "no-response"}
				}
			}
		}
	}
	var live []string
	for ip, h := range hosts {
		if h.alive {
			live = append(live, ip)
		}
	}
	sort.Strings(live)

	var obs []*Observation
	if !sc.sp.Empty() && len(live) > 0 {
		r3, _, err := nmap.Services(ctx, sc.opts, live, sc.sp.NmapArg(), len(sc.sp.UDP) > 0)
		if err != nil {
			return nil, nil, err
		}
		for _, h := range r3.Hosts {
			ip := h.IP()
			if !sc.scope[ip] {
				continue
			}
			if hr := hosts[ip]; hr != nil && hr.hostname == "" {
				hr.hostname = h.Hostname()
			}
			for _, p := range h.Ports {
				if p.State.State != "open" {
					continue
				}
				o := &Observation{IP: ip, Port: p.PortID, Proto: p.Protocol, State: p.State.State, Service: p.Service.Name,
					Product: p.Service.Product, Version: p.Service.Version}
				o.Data.Banner = Banner{Product: p.Service.Product, Version: p.Service.Version, ExtraInfo: p.Service.ExtraInfo,
					Tunnel: p.Service.Tunnel, Method: p.Service.Method, Conf: p.Service.Conf, CPE: p.Service.CPE,
					DevType: p.Service.DevType, OSType: p.Service.OSType}
				if names := sc.hostnames[ip]; len(names) > 0 {
					o.Data.Hostname = names[0]
				} else if hr := hosts[ip]; hr != nil {
					o.Data.Hostname = hr.hostname
				}
				if hr := hosts[ip]; hr != nil {
					o.Data.MAC, o.Data.Vendor = hr.mac, hr.vendor
				}
				obs = append(obs, o)
			}
		}
	}
	// sonda HTTP (równolegle, ze wspólnym limitem tempa) + sygnatury
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, o := range obs {
		if sc.cfg.HTTPProbe && httpCandidate(o) {
			wg.Add(1)
			go func(o *Observation) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				prefer := o.Data.Banner.Tunnel == "ssl" || strings.Contains(o.Service, "https") || strings.Contains(o.Service, "ssl") || o.Port == 443 || o.Port == 8443
				hn := ""
				if names := sc.hostnames[o.IP]; len(names) > 0 {
					hn = names[0]
				}
				r := sc.prober.Probe(ctx, o.IP, o.Port, hn, prefer)
				if r.Error == "" || r.Status > 0 {
					o.Data.HTTP = r
					if sc.cfg.HTTPProbe && r.Error == "" {
						sc.prober.FetchPaths(ctx, r, o.IP, o.Port, hn, e.Sigs.PathsFor(SigInput(o), 25, !sc.noGeneric))
					}
				}
			}(o)
		}
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	ensurePortRules(e.S.DB, obs)
	for _, o := range obs {
		o.Data.Detections = e.Sigs.Evaluate(SigInput(o))
		o.Finalize()
		Score(o)
	}
	return hosts, obs, nil
}

func httpCandidate(o *Observation) bool {
	if o.Proto != "tcp" {
		return false
	}
	s := o.Service
	switch {
	case strings.Contains(s, "http"), s == "", s == "unknown", s == "tcpwrapped", strings.Contains(s, "ssl"), o.Data.Banner.Tunnel == "ssl":
		return true
	case o.Data.Banner.Method == "table" || o.Data.Banner.Method == "":
		// nmap nie rozpoznał usługi (nazwa tylko z tabeli portów): sprawdzamy, czy to nie HTTP
		return true
	}
	switch s {
	case "ssh", "ftp", "smtp", "mysql", "postgresql", "redis", "ms-wbt-server", "microsoft-ds", "netbios-ssn", "domain",
		"telnet", "vnc", "imap", "pop3", "ldap", "mongodb", "rtsp", "snmp", "msrpc", "rpcbind", "nfs", "smux":
		return false
	}
	return standardHTTP[o.Port] || (o.Port >= 8000 && o.Port <= 8999)
}

func (e *Engine) saveJob(sc *scanCtx, job []block, ips []string, hosts map[string]*hostRes, obs []*Observation, nips, worker int, dur time.Duration) error {
	tx, err := e.S.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	liveN := 0
	for _, h := range hosts {
		if h.alive {
			liveN++
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO scan_hosts(scan_id,ip,alive,hostname,reason,retried) VALUES(?,?,?,?,?,?)`,
			sc.id, h.ip, b2i(h.alive), h.hostname, h.reason, b2i(h.retried)); err != nil {
			return err
		}
	}
	ApplyOverrides(e.S.DB, obs) // poprawki analityka przetrwają kolejne skany
	for _, o := range obs {
		if err := InsertObservation(tx, e.S, sc.id, o); err != nil {
			return err
		}
	}
	perBlock := dur.Milliseconds() / int64(max(1, len(job)))
	for _, b := range job {
		live := 0
		for _, ip := range b.ips {
			if h := hosts[ip]; h != nil && h.alive {
				live++
			}
		}
		if _, err := tx.Exec(`UPDATE scan_blocks SET status='done', duration_ms=?, live=? WHERE id=?`, perBlock, live, b.id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO scan_jobs(scan_id,ips,live,services,started_at,duration_ms,worker,status) VALUES(?,?,?,?,?,?,?,'done')`,
		sc.id, nips, liveN, len(obs), time.Now().Add(-dur).UTC().Format(time.RFC3339), dur.Milliseconds(), worker+1); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE scans SET done_ips=done_ips+?, live_hosts=live_hosts+?, open_services=open_services+? WHERE id=?`,
		nips, liveN, len(obs), sc.id); err != nil {
		return err
	}
	// baza urządzeń aktualizowana na bieżąco: wyniki tej podgrupy są widoczne od razu, bez czekania na koniec skanu
	if err := updateInventory(tx, sc.id, ips, hosts, obs, sc.sp, sc.cfg.GoneAfter, time.Now().Hour(), store.Now(), false); err != nil {
		return err
	}
	return tx.Commit()
}

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// InsertObservation: zapis obserwacji; banery, nagłówki, ciasteczka, tytuł, certyfikat są w zaszyfrowanym blobie.
func InsertObservation(tx execer, s *store.Store, scanID int64, o *Observation) error {
	blob, _ := json.Marshal(o.Data)
	if o.SeenAt == "" {
		o.SeenAt = store.Now()
	}
	if o.Rules == nil {
		o.Rules = []string{}
	}
	res, err := tx.Exec(`INSERT OR REPLACE INTO observations(scan_id,ip,port,proto,state,service,product,version,tls,http_status,techs,flags,
interest,data_enc,fingerprint,seen_at,rules,response_ms,edited,edited_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, scanID, o.IP, o.Port, o.Proto, o.State, o.Service, o.Product,
		o.Version, b2i(o.TLS), o.HTTPStatus, store.ToJSON(o.Techs), store.ToJSON(o.Flags), o.Interest, s.Box.Seal(string(blob)), o.Fingerprint, o.SeenAt, store.ToJSON(o.Rules), o.ResponseMs, b2i(o.Edited), o.EditedBy)
	if err == nil {
		o.ID, _ = res.LastInsertId()
		o.ScanID = scanID
		err = TrackTechs(tx, scanID, o)
	}
	return err
}

// TrackTechs: katalog technologii (tabela technologies): kiedy i w którym skanie technologia pojawiła się
// pierwszy i ostatni raz. Na tej podstawie zakładka Technologie pokazuje „tylko nowe” w wybranym okresie.
func TrackTechs(tx execer, scanID int64, o *Observation) error {
	for _, t := range o.Techs {
		if t.ID == "" {
			continue
		}
		_, err := tx.Exec(`INSERT INTO technologies(id,name,category,first_seen,first_scan_id,last_seen,last_scan_id,sightings) VALUES(?,?,?,?,?,?,?,1)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, category=excluded.category,
  first_seen=CASE WHEN excluded.first_seen < first_seen THEN excluded.first_seen ELSE first_seen END,
  first_scan_id=CASE WHEN excluded.first_scan_id < first_scan_id THEN excluded.first_scan_id ELSE first_scan_id END,
  last_seen=CASE WHEN excluded.last_seen > last_seen THEN excluded.last_seen ELSE last_seen END,
  last_scan_id=CASE WHEN excluded.last_scan_id > last_scan_id THEN excluded.last_scan_id ELSE last_scan_id END,
  sightings=sightings+1`, t.ID, t.Name, t.Category, o.SeenAt, scanID, o.SeenAt, scanID)
		if err != nil {
			return err
		}
	}
	return nil
}

// BackfillTechs: jednorazowe zbudowanie katalogu technologii z całej historii obserwacji (gdy tabela jest pusta).
func BackfillTechs(s *store.Store) (int, error) {
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM technologies`).Scan(&n); err != nil || n > 0 {
		return 0, err
	}
	rows, err := s.DB.Query(`SELECT scan_id, COALESCE(NULLIF(seen_at,''),(SELECT COALESCE(NULLIF(started_at,''),created_at) FROM scans WHERE scans.id=observations.scan_id)), techs FROM observations ORDER BY id`)
	if err != nil {
		return 0, err
	}
	type rec struct {
		sid  int64
		at   string
		tech []Tech
	}
	var list []rec
	for rows.Next() {
		var r rec
		var tj string
		_ = rows.Scan(&r.sid, &r.at, &tj)
		_ = json.Unmarshal([]byte(tj), &r.tech)
		list = append(list, r)
	}
	rows.Close()
	tx, err := s.DB.Begin()
	if err != nil {
		return 0, err
	}
	for _, r := range list {
		if err := TrackTechs(tx, r.sid, &Observation{SeenAt: r.at, Techs: r.tech}); err != nil {
			tx.Rollback()
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.TechBaseline() // świeża instalacja: pierwszy inwentarz to stan wyjściowy
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM technologies`).Scan(&n)
	return n, nil
}
