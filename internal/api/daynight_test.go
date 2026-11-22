package api

import "testing"

func TestNightOff(t *testing.T) {
	mk := func(nightSeen, daySeen int) *hostOut {
		seen, scan := make([]int, 24), make([]int, 24)
		for h := 0; h < 24; h++ {
			scan[h] = 4
			if h >= 22 || h < 6 {
				seen[h] = nightSeen
			} else {
				seen[h] = daySeen
			}
		}
		h := &hostOut{}
		h.NightSeen, h.NightScan, h.DaySeen, h.DayScan = dayNight(seen, scan)
		return h
	}
	cases := []struct {
		night, day int
		want       bool
	}{{0, 4, true}, {1, 4, true}, {4, 4, false}, {0, 0, false}, {2, 4, false}}
	for _, c := range cases {
		if got := nightOff(mk(c.night, c.day)); got != c.want {
			t.Errorf("noc %d, dzień %d: %v, oczekiwano %v", c.night, c.day, got, c.want)
		}
	}
	if nightOff(&hostOut{DaySeen: 5}) {
		t.Error("bez pomiarów nocnych nie wolno oznaczać jako niestabilna")
	}
}
