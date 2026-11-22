package scheduler

import (
	"testing"
	"time"

	"github.com/asi-agh/asi/internal/scan"
)

// Uzgodnienie z AGH: skan nocny 22–06, a doskaner w dzień; w oknie nocnym doskaner nie pracuje.
func TestRetryWindowVsNightWindow(t *testing.T) {
	c := &scan.Config{SchedEnabled: true, WinStart: "22:00", WinEnd: "06:00", WinDays: "1234567",
		RetryEnabled: true, RetryStart: "06:00", RetryEnd: "22:00"}
	s := &Scheduler{}
	at := func(h, m int) time.Time { return time.Date(2026, 11, 23, h, m, 0, 0, time.Local) }
	cases := []struct {
		t    time.Time
		want bool
	}{
		{at(12, 0), true},   // dzień: doskaner
		{at(23, 30), false}, // noc: pełny skan, doskaner stoi
		{at(3, 0), false},   // noc po północy
		{at(6, 30), true},
	}
	for _, k := range cases {
		if got := s.retryWindowOpen(c, k.t); got != k.want {
			t.Errorf("%s: doskaner=%v, oczekiwano %v", k.t.Format("15:04"), got, k.want)
		}
	}
	// bez harmonogramu doskaner zależy tylko od własnego okna
	c.SchedEnabled = false
	if !s.retryWindowOpen(c, at(12, 0)) || s.retryWindowOpen(c, at(23, 0)) {
		t.Error("okno doskanera bez harmonogramu")
	}
}

// Skan nocny przerwany o 06:00 musi dostać koniec okna jako deadline i wznowić się w kolejnym oknie.
func TestNightWindowDeadline(t *testing.T) {
	c := &scan.Config{SchedEnabled: true, WinStart: "22:00", WinEnd: "06:00", WinDays: "1234567"}
	in, end := scan.InWindow(c, time.Date(2026, 11, 23, 23, 0, 0, 0, time.Local))
	if !in || end.Hour() != 6 || end.Day() != 24 {
		t.Fatalf("okno 22–06 o 23:00: in=%v koniec=%v", in, end)
	}
	if in, _ := scan.InWindow(c, time.Date(2026, 11, 24, 7, 0, 0, 0, time.Local)); in {
		t.Fatal("07:00 nie należy do okna nocnego")
	}
	next := scan.NextWindowStart(c, time.Date(2026, 11, 24, 7, 0, 0, 0, time.Local))
	if next.Hour() != 22 || next.Day() != 24 {
		t.Fatalf("następne okno: %v", next)
	}
}
