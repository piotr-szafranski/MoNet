// Package ports: parsowanie listy portów podanej przez użytkownika przed skanem.
// Format: "22,80,443,8000-8100", z prefiksami protokołu "T:22,80,U:53,161" (jak w nmap).
package ports

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const MaxPorts = 20000

type Spec struct {
	TCP []int `json:"tcp"`
	UDP []int `json:"udp"`
}

var Presets = map[string]string{
	"web":      "80,81,443,591,2082,2083,2086,2087,3000,4443,5000,5601,7001,7443,8000,8008,8080,8081,8088,8180,8443,8888,9000,9090,9200,9443,10000",
	"top100":   "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157",
	"infra":    "21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,587,636,993,995,1433,1521,2049,3306,3389,5432,5900,5985,6379,8080,8443,9200,11211,27017",
	"discover": "",
}

// Parse waliduje i normalizuje specyfikację portów.
func Parse(s string) (Spec, error) {
	var sp Spec
	s = strings.TrimSpace(s)
	if p, ok := Presets[strings.ToLower(s)]; ok {
		s = p
	}
	if s == "" {
		return sp, nil
	}
	tcp, udp := map[int]bool{}, map[int]bool{}
	cur := tcp
	for _, raw := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\n' }) {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			continue
		}
		up := strings.ToUpper(tok)
		switch {
		case strings.HasPrefix(up, "T:"):
			cur, tok = tcp, tok[2:]
		case strings.HasPrefix(up, "U:"):
			cur, tok = udp, tok[2:]
		}
		if tok == "" {
			continue
		}
		lo, hi := tok, tok
		if i := strings.Index(tok, "-"); i >= 0 {
			lo, hi = tok[:i], tok[i+1:]
		}
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		b, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil {
			return sp, fmt.Errorf("niepoprawny port lub zakres: %q", raw)
		}
		if a < 1 || b > 65535 || a > b {
			return sp, fmt.Errorf("port poza zakresem 1-65535: %q", raw)
		}
		if len(tcp)+len(udp)+(b-a+1) > MaxPorts {
			return sp, fmt.Errorf("za dużo portów (limit %d)", MaxPorts)
		}
		for p := a; p <= b; p++ {
			cur[p] = true
		}
	}
	sp.TCP, sp.UDP = keys(tcp), keys(udp)
	return sp, nil
}

func keys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func (s Spec) Empty() bool { return len(s.TCP) == 0 && len(s.UDP) == 0 }
func (s Spec) Count() int  { return len(s.TCP) + len(s.UDP) }

// NmapArg zwraca wartość dla -p (z kompresją zakresów).
func (s Spec) NmapArg() string {
	var parts []string
	if len(s.TCP) > 0 {
		parts = append(parts, "T:"+compress(s.TCP))
	}
	if len(s.UDP) > 0 {
		parts = append(parts, "U:"+compress(s.UDP))
	}
	return strings.Join(parts, ",")
}

// String: czytelna, znormalizowana postać (do zapisu w snapshotcie skanu).
func (s Spec) String() string {
	if len(s.UDP) == 0 {
		return compress(s.TCP)
	}
	return s.NmapArg()
}

func compress(ps []int) string {
	var b strings.Builder
	for i := 0; i < len(ps); {
		j := i
		for j+1 < len(ps) && ps[j+1] == ps[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		if j > i {
			fmt.Fprintf(&b, "%d-%d", ps[i], ps[j])
		} else {
			fmt.Fprintf(&b, "%d", ps[i])
		}
		i = j + 1
	}
	return b.String()
}

// Contains: czy port danego protokołu był w specyfikacji (do uczciwego diffu).
func (s Spec) Contains(proto string, port int) bool {
	list := s.TCP
	if proto == "udp" {
		list = s.UDP
	}
	i := sort.SearchInts(list, port)
	return i < len(list) && list[i] == port
}
