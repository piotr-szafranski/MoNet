// Package diff: porównanie dwóch skanów. Porównujemy tylko adresy i porty objęte OBOMA skanami,
// żeby zmiana zakresu lub listy portów nie dawała fałszywych „zniknięć”.
package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/asi-agh/asi/internal/ports"
	"github.com/asi-agh/asi/internal/scan"
	"github.com/asi-agh/asi/internal/store"
)

type FieldChange struct {
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

type ServiceChange struct {
	Kind     string        `json:"kind"` // new | returned | gone | changed
	IP       string        `json:"ip"`
	Port     int           `json:"port"`
	Proto    string        `json:"proto"`
	Service  string        `json:"service"`
	Product  string        `json:"product"`
	Title    string        `json:"title,omitempty"`
	Interest int           `json:"interest"`
	ObsID    int64         `json:"obs_id"`
	Changes  []FieldChange `json:"changes,omitempty"`
}

type HostChange struct {
	Kind     string `json:"kind"` // new | returned | gone
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Retried  bool   `json:"retried,omitempty"`
}

type ScanMeta struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Started  string `json:"started_at"`
	Finished string `json:"finished_at"`
	Ports    string `json:"ports"`
	Live     int    `json:"live_hosts"`
	Services int    `json:"open_services"`
}

type Result struct {
	A             ScanMeta        `json:"a"`
	B             ScanMeta        `json:"b"`
	ComparedIPs   int             `json:"compared_ips"`
	ComparedPorts string          `json:"compared_ports"`
	Hosts         []HostChange    `json:"hosts"`
	Services      []ServiceChange `json:"services"`
	Summary       map[string]int  `json:"summary"`
	Notes         []string        `json:"notes,omitempty"`
}

func meta(s *store.Store, id int64) (ScanMeta, error) {
	m := ScanMeta{ID: id}
	err := s.DB.QueryRow(`SELECT name,started_at,finished_at,ports,live_hosts,open_services FROM scans WHERE id=?`, id).
		Scan(&m.Name, &m.Started, &m.Finished, &m.Ports, &m.Live, &m.Services)
	return m, err
}

func scope(s *store.Store, id int64) map[string]bool {
	out := map[string]bool{}
	rows, err := s.DB.Query(`SELECT ips FROM scan_blocks WHERE scan_id=?`, id)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var ips string
		_ = rows.Scan(&ips)
		for _, ip := range strings.Split(ips, "\n") {
			out[ip] = true
		}
	}
	rows.Close()
	// doskanowanie i import nie mają bloków: zakresem są adresy faktycznie sprawdzone (najświeższe rekordy)
	hr, err := s.DB.Query(`SELECT ip FROM scan_hosts WHERE scan_id=?`, id)
	if err == nil {
		defer hr.Close()
		for hr.Next() {
			var ip string
			_ = hr.Scan(&ip)
			out[ip] = true
		}
	}
	return out
}

func aliveHosts(s *store.Store, id int64) map[string][2]string {
	out := map[string][2]string{}
	rows, err := s.DB.Query(`SELECT ip,hostname,retried FROM scan_hosts WHERE scan_id=? AND alive=1`, id)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var ip, hn string
		var r int
		_ = rows.Scan(&ip, &hn, &r)
		out[ip] = [2]string{hn, fmt.Sprint(r)}
	}
	return out
}

func intersectSpec(a, b ports.Spec) ports.Spec {
	var out ports.Spec
	for _, p := range a.TCP {
		if b.Contains("tcp", p) {
			out.TCP = append(out.TCP, p)
		}
	}
	for _, p := range a.UDP {
		if b.Contains("udp", p) {
			out.UDP = append(out.UDP, p)
		}
	}
	return out
}

func Compute(s *store.Store, a, b int64) (*Result, error) {
	ma, err := meta(s, a)
	if err != nil {
		return nil, fmt.Errorf("skan %d: %w", a, err)
	}
	mb, err := meta(s, b)
	if err != nil {
		return nil, fmt.Errorf("skan %d: %w", b, err)
	}
	// puste listy jako [] (nie null): frontend zawsze dostaje tablice
	r := &Result{A: ma, B: mb, Summary: map[string]int{}, Hosts: []HostChange{}, Services: []ServiceChange{}, Notes: []string{}}
	sa, sb := scope(s, a), scope(s, b)
	both := map[string]bool{}
	for ip := range sa {
		if sb[ip] {
			both[ip] = true
		}
	}
	// skany zaimportowane nie mają bloków: wtedy zakresem są hosty obecne w którymkolwiek
	ha, hb := aliveHosts(s, a), aliveHosts(s, b)
	if len(sa) == 0 || len(sb) == 0 {
		r.Notes = append(r.Notes, "co najmniej jeden skan pochodzi z importu: zakres porównania = hosty z obu wyników")
		for ip := range ha {
			both[ip] = true
		}
		for ip := range hb {
			both[ip] = true
		}
	}
	r.ComparedIPs = len(both)
	pa, _ := ports.Parse(ma.Ports)
	pb, _ := ports.Parse(mb.Ports)
	common := intersectSpec(pa, pb)
	r.ComparedPorts = common.String()
	if pa.String() != pb.String() {
		r.Notes = append(r.Notes, fmt.Sprintf("listy portów różnią się (A: %s, B: %s): porównano tylko wspólne porty", ma.Ports, mb.Ports))
	}

	for ip, v := range hb {
		if both[ip] {
			if _, ok := ha[ip]; !ok {
				kind := "new"
				if seenBefore(s, `SELECT 1 FROM scan_hosts WHERE ip=? AND alive=1 AND scan_id<? LIMIT 1`, ip, a) {
					kind = "returned" // był widziany w którymś wcześniejszym skanie: powrót, a nie nowy host
				}
				r.Hosts = append(r.Hosts, HostChange{Kind: kind, IP: ip, Hostname: v[0]})
			}
		}
	}
	for ip, v := range ha {
		if both[ip] {
			if _, ok := hb[ip]; !ok {
				r.Hosts = append(r.Hosts, HostChange{Kind: "gone", IP: ip, Hostname: v[0]})
			}
		}
	}
	sort.Slice(r.Hosts, func(i, j int) bool { return r.Hosts[i].Kind+r.Hosts[i].IP < r.Hosts[j].Kind+r.Hosts[j].IP })

	oa, err := scan.ListObs(s, `WHERE scan_id=?`, true, a)
	if err != nil {
		return nil, err
	}
	ob, err := scan.ListObs(s, `WHERE scan_id=?`, true, b)
	if err != nil {
		return nil, err
	}
	key := func(o *scan.Observation) string { return fmt.Sprintf("%s|%d|%s", o.IP, o.Port, o.Proto) }
	ma2 := map[string]*scan.Observation{}
	for _, o := range oa {
		if both[o.IP] && (common.Contains(o.Proto, o.Port) || common.Empty()) {
			ma2[key(o)] = o
		}
	}
	mb2 := map[string]*scan.Observation{}
	for _, o := range ob {
		if both[o.IP] && (common.Contains(o.Proto, o.Port) || common.Empty()) {
			mb2[key(o)] = o
		}
	}
	for k, o := range mb2 {
		prev, ok := ma2[k]
		switch {
		case !ok:
			kind := "new"
			if seenBefore(s, `SELECT 1 FROM observations WHERE ip=? AND port=? AND proto=? AND scan_id<? LIMIT 1`, o.IP, o.Port, o.Proto, a) {
				kind = "returned"
			}
			r.Services = append(r.Services, sc(kind, o, nil))
		case prev.Fingerprint != o.Fingerprint:
			if ch := fields(prev, o); len(ch) > 0 {
				r.Services = append(r.Services, sc("changed", o, ch))
			}
		}
	}
	for k, o := range ma2 {
		if _, ok := mb2[k]; !ok {
			r.Services = append(r.Services, sc("gone", o, nil))
		}
	}
	sort.Slice(r.Services, func(i, j int) bool {
		if r.Services[i].Kind != r.Services[j].Kind {
			return r.Services[i].Kind < r.Services[j].Kind
		}
		return r.Services[i].Interest > r.Services[j].Interest
	})
	for _, h := range r.Hosts {
		r.Summary["hosts_"+h.Kind]++
	}
	for _, x := range r.Services {
		r.Summary["services_"+x.Kind]++
	}
	return r, nil
}

// seenBefore: czy zapytanie zwraca jakikolwiek wiersz (obiekt widziany we wcześniejszym skanie).
func seenBefore(s *store.Store, q string, args ...any) bool {
	var one int
	return s.DB.QueryRow(q, args...).Scan(&one) == nil
}

func sc(kind string, o *scan.Observation, ch []FieldChange) ServiceChange {
	x := ServiceChange{Kind: kind, IP: o.IP, Port: o.Port, Proto: o.Proto, Service: o.Service, Product: strings.TrimSpace(o.Product + " " + o.Version),
		Interest: o.Interest, ObsID: o.ID, Changes: ch}
	if o.Data.HTTP != nil {
		x.Title = o.Data.HTTP.Title
	}
	return x
}

func techStr(o *scan.Observation) string {
	var t []string
	for _, x := range o.Techs {
		s := x.Name
		if x.Version != "" {
			s += " " + x.Version
		}
		t = append(t, s)
	}
	sort.Strings(t)
	return strings.Join(t, ", ")
}

func fields(a, b *scan.Observation) []FieldChange {
	var out []FieldChange
	add := func(f, x, y string) {
		if x != y {
			out = append(out, FieldChange{Field: f, Before: x, After: y})
		}
	}
	add("usługa", a.Service, b.Service)
	add("produkt", a.Product, b.Product)
	add("wersja", a.Version, b.Version)
	add("kod HTTP", fmt.Sprint(a.HTTPStatus), fmt.Sprint(b.HTTPStatus))
	if la, lb := scan.LatencyBucket(a.ResponseMs), scan.LatencyBucket(b.ResponseMs); la != "" && lb != "" && la != lb {
		out = append(out, FieldChange{Field: "czas odpowiedzi", Before: fmt.Sprintf("%d ms, %s", a.ResponseMs, la), After: fmt.Sprintf("%d ms, %s", b.ResponseMs, lb)})
	}
	ha, hb := a.Data.HTTP, b.Data.HTTP
	ta, tb, sa, sb, ca, cb := "", "", "", "", "", ""
	if ha != nil {
		ta, sa = ha.Title, strings.Join(ha.Headers["server"], ",")
		if ha.TLS != nil {
			ca = ha.TLS.SHA256[:16] + " (" + ha.TLS.SubjectCN + ")"
		}
	}
	if hb != nil {
		tb, sb = hb.Title, strings.Join(hb.Headers["server"], ",")
		if hb.TLS != nil {
			cb = hb.TLS.SHA256[:16] + " (" + hb.TLS.SubjectCN + ")"
		}
	}
	add("tytuł", ta, tb)
	add("nagłówek Server", sa, sb)
	add("certyfikat", ca, cb)
	add("technologie", techStr(a), techStr(b))
	return out
}
