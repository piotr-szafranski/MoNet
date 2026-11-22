package scan

import (
	"testing"
	"time"
)

func at(h, m int, wd time.Weekday) time.Time {
	// 2026-11-16 to poniedziałek
	base := time.Date(2026, 11, 16, h, m, 0, 0, time.Local)
	return base.AddDate(0, 0, (int(wd)+6)%7)
}

func TestWindowOvernight(t *testing.T) {
	c := &Config{WinStart: "22:00", WinEnd: "06:00", WinDays: "12345"} // pn-pt
	cases := []struct {
		t    time.Time
		in   bool
		name string
	}{
		{at(23, 0, time.Monday), true, "pn 23:00"},
		{at(5, 59, time.Tuesday), true, "wt 05:59 (okno z poniedziałku)"},
		{at(6, 0, time.Tuesday), false, "wt 06:00 koniec"},
		{at(12, 0, time.Wednesday), false, "śr 12:00"},
		{at(23, 0, time.Saturday), false, "sobota wyłączona"},
		{at(3, 0, time.Saturday), true, "so 03:00 (okno z piątku)"},
		{at(3, 0, time.Monday), false, "pn 03:00 (niedziela wyłączona)"},
	}
	for _, x := range cases {
		in, end := InWindow(c, x.t)
		if in != x.in {
			t.Errorf("%s: oczekiwano %v", x.name, x.in)
		}
		if in && !end.After(x.t) {
			t.Errorf("%s: koniec okna %v przed %v", x.name, end, x.t)
		}
	}
	n := NextWindowStart(c, at(12, 0, time.Wednesday))
	if n.Hour() != 22 || n.Weekday() != time.Wednesday {
		t.Errorf("następne okno: %v", n)
	}
}

func TestWindowDay(t *testing.T) {
	c := &Config{WinStart: "08:00", WinEnd: "16:00", WinDays: "1234567"}
	if in, end := InWindow(c, at(9, 0, time.Monday)); !in || end.Hour() != 16 {
		t.Fatal("09:00 powinno być w oknie do 16:00")
	}
	if in, _ := InWindow(c, at(16, 30, time.Monday)); in {
		t.Fatal("16:30 poza oknem")
	}
}

func TestStates(t *testing.T) {
	cases := []struct {
		hist  string
		miss  int
		state string
	}{
		{"1111", 0, "active"},
		{"1110", 1, "missing"},
		{"11100", 2, "missing"},
		{"111000", 3, "gone"},
		{"10101", 0, "unstable"},
		{"1101", 0, "unstable"},
	}
	for _, c := range cases {
		if s := computeState(c.hist, c.miss, 3); s != c.state {
			t.Errorf("%s/%d: %s, oczekiwano %s", c.hist, c.miss, s, c.state)
		}
	}
	h := ""
	for i := 0; i < 30; i++ {
		h = pushHistory(h, i%2 == 0)
	}
	if len(h) != historyLen {
		t.Fatalf("historia %d", len(h))
	}
}

func TestPlannerAdapts(t *testing.T) {
	a := &activeScan{}
	p := &planner{k: 4, target: 30, a: a}
	for i := 0; i < 100; i++ {
		p.pending = append(p.pending, block{id: int64(i)})
	}
	p.report(256, 10*time.Second) // 25.6 IP/s → 768 IP na 30 s → 12 bloków
	if p.k != 12 {
		t.Fatalf("k=%d", p.k)
	}
	p.report(64, 60*time.Second) // wolno → zmniejszenie
	if p.k >= 12 {
		t.Fatalf("planer nie zmniejszył podgrupy: k=%d", p.k)
	}
}
