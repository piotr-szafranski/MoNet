// Package scheduler: cykliczne skany w oknach czasowych. Skan, który nie zmieścił się w oknie,
// jest zatrzymywany (koniec okna = deadline kontekstu) i wznawiany od miejsca przerwania w kolejnym oknie.
package scheduler

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/asi-agh/asi/internal/scan"
	"github.com/asi-agh/asi/internal/store"
)

type Scheduler struct {
	S       *store.Store
	E       *scan.Engine
	Log     *log.Logger
	workers sync.Map // config_id → doskaner działa
}

func (s *Scheduler) Run(ctx context.Context) {
	// po restarcie serwera skany przerwane w trakcie są wznawiane automatycznie od miejsca przerwania
	// (harmonogramowe tylko wtedy, gdy ich okno jest otwarte; w przeciwnym razie czekają na kolejne okno)
	rows, err := s.S.DB.Query(`SELECT id, COALESCE(config_id,0) FROM scans WHERE status IN ('running','queued') AND source='scan'`)
	type pend struct{ id, cfg int64 }
	var list []pend
	if err == nil {
		for rows.Next() {
			var p pend
			_ = rows.Scan(&p.id, &p.cfg)
			list = append(list, p)
		}
		rows.Close()
	}
	_, _ = s.S.DB.Exec(`UPDATE scans SET status='paused' WHERE status IN ('running','queued') AND source='scan'`)
	for _, p := range list {
		var deadline time.Time
		if c, err := scan.GetConfig(s.S.DB, p.cfg); err == nil && c.SchedEnabled {
			in, end := scan.InWindow(c, time.Now())
			if !in {
				continue
			}
			deadline = end
		}
		s.Log.Printf("restart: wznawiam przerwany skan %d", p.id)
		_ = s.E.Start(p.id, deadline)
	}
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	s.tick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tick()
		}
	}
}

func (s *Scheduler) tick() {
	cfgs, err := scan.ListConfigs(s.S.DB)
	if err != nil {
		return
	}
	now := time.Now()
	for _, c := range cfgs {
		s.retryTick(c, now)
		if !c.SchedEnabled {
			continue
		}
		in, end := scan.InWindow(c, now)
		if !in {
			continue
		}
		// 1) wznowienie skanu wstrzymanego po poprzednim oknie
		var pausedID int64
		_ = s.S.DB.QueryRow(`SELECT id FROM scans WHERE config_id=? AND status='paused' AND source='scan' ORDER BY id DESC LIMIT 1`, c.ID).Scan(&pausedID)
		if pausedID > 0 {
			if !s.E.IsActive(pausedID) {
				s.Log.Printf("harmonogram: wznawiam skan %d (konfiguracja %q) do %s", pausedID, c.Name, end.Format("15:04"))
				_ = s.E.Start(pausedID, end)
			}
			continue
		}
		if s.E.ActiveForConfig(c.ID) {
			continue
		}
		// 2) nowy przebieg, jeśli minął interwał
		due := c.NextRun == ""
		if t, err := time.Parse(time.RFC3339, c.NextRun); err == nil && !now.Before(t) {
			due = true
		}
		if !due {
			continue
		}
		id, err := s.E.CreateScan(context.Background(), c, nil, "harmonogram", "")
		next := now.Add(time.Duration(c.SchedEveryMin) * time.Minute)
		if ok, _ := scan.InWindow(c, next); !ok {
			next = scan.NextWindowStart(c, next)
		}
		_, _ = s.S.DB.Exec(`UPDATE scan_configs SET next_run=? WHERE id=?`, next.UTC().Format(time.RFC3339), c.ID)
		if err != nil {
			s.Log.Printf("harmonogram: konfiguracja %q: %v", c.Name, err)
			continue
		}
		s.Log.Printf("harmonogram: start skanu %d (konfiguracja %q), okno do %s", id, c.Name, end.Format("15:04"))
		_ = s.E.Start(id, end)
	}
}

// retryTick: uruchamia (jeśli trzeba) ciągły doskaner dla konfiguracji.
func (s *Scheduler) retryTick(c *scan.Config, now time.Time) {
	if !c.RetryEnabled || !s.retryWindowOpen(c, now) {
		return
	}
	if _, running := s.workers.LoadOrStore(c.ID, true); running {
		return
	}
	s.Log.Printf("doskaner %q: start (okno %s–%s, %d adr. naraz, przerwa %ds)", c.Name, c.RetryStart, c.RetryEnd, c.RetryBatch, c.RetryPauseSec)
	go s.retryWorker(c.ID)
}

func (s *Scheduler) retryWindowOpen(c *scan.Config, now time.Time) bool {
	if c.SchedEnabled {
		if in, _ := scan.InWindow(c, now); in {
			return false // w głównym oknie pracuje pełny skan
		}
	}
	in, _ := scan.InWindow(c.RetryWindow(), now)
	return in
}

// retryWorker: sekwencyjne doskanowanie nieosiągniętych końcówek, adres po adresie (domyślnie 1 naraz),
// z przerwą między kolejnymi. Każdy wynik trafia od razu do bazy. Lista jest obiegana w kółko: najpierw adresy
// sprawdzane najdawniej, więc w ciągu dnia każda końcówka jest sprawdzana wielokrotnie.
func (s *Scheduler) retryWorker(cfgID int64) {
	defer s.workers.Delete(cfgID)
	for {
		c, err := scan.GetConfig(s.S.DB, cfgID)
		if err != nil || !c.RetryEnabled || !s.retryWindowOpen(c, time.Now()) {
			s.Log.Printf("doskaner konfiguracji %d: koniec okna", cfgID)
			return
		}
		if s.E.ActiveForConfig(cfgID) {
			time.Sleep(30 * time.Second)
			continue
		}
		ips, err := s.E.RetryCandidates(cfgID, c.RetryBatch)
		if err != nil || len(ips) == 0 {
			time.Sleep(60 * time.Second)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		if _, err := s.E.RetryBatch(ctx, c, ips); err != nil {
			s.Log.Printf("doskaner %q: %v", c.Name, err)
		}
		cancel()
		_, _ = s.S.DB.Exec(`UPDATE scan_configs SET retry_next=? WHERE id=?`, time.Now().Add(time.Duration(c.RetryPauseSec)*time.Second).UTC().Format(time.RFC3339), cfgID)
		time.Sleep(time.Duration(c.RetryPauseSec) * time.Second)
	}
}
