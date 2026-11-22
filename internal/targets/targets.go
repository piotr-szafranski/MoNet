// Package targets: parsowanie celów (IP, CIDR, zakresy, domeny), import CSV/JSON i rozwijanie do listy adresów.
package targets

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

const MaxExpand = 1 << 20 // twardy limit adresów na skan (1 048 576)

type Kind string

const (
	KindIP     Kind = "ip"
	KindCIDR   Kind = "cidr"
	KindRange  Kind = "range"
	KindDomain Kind = "domain"
)

type Input struct {
	Value string   `json:"value"`
	Tags  []string `json:"tags,omitempty"`
	Note  string   `json:"note,omitempty"`
}

var numericLike = regexp.MustCompile(`^[0-9.\-/ ]+$`)

var domainRe = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}\.?$`)

// Classify normalizuje wartość i określa rodzaj celu.
func Classify(v string) (string, Kind, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", "", errors.New("pusty cel")
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return a.Unmap().String(), KindIP, nil
	}
	if p, err := netip.ParsePrefix(v); err == nil {
		p = p.Masked()
		if p.Addr().Is4() && p.Bits() < 8 || p.Addr().Is6() && p.Bits() < 112 {
			return "", "", fmt.Errorf("zakres %s jest zbyt duży", v)
		}
		return p.String(), KindCIDR, nil
	}
	if i := strings.Index(v, "-"); i > 0 {
		a, err1 := netip.ParseAddr(strings.TrimSpace(v[:i]))
		rest := strings.TrimSpace(v[i+1:])
		b, err2 := netip.ParseAddr(rest)
		if err1 == nil && err2 != nil && a.Is4() { // 10.0.0.1-50
			var last int
			if _, err := fmt.Sscanf(rest, "%d", &last); err == nil && last >= 0 && last <= 255 {
				o := a.As4()
				o[3] = byte(last)
				b, err2 = netip.AddrFrom4(o), nil
			}
		}
		if err1 == nil && err2 == nil && a.Is4() == b.Is4() && !b.Less(a) {
			return a.String() + "-" + b.String(), KindRange, nil
		}
		if err1 == nil && err2 == nil && b.Less(a) {
			return "", "", fmt.Errorf("odwrócony zakres %q: początek większy niż koniec", v)
		}
	}
	d := strings.ToLower(strings.TrimSuffix(v, "."))
	if numericLike.MatchString(strings.SplitN(d, "/", 2)[0]) {
		// np. 10.66.8.300 albo 10.66.8.0/33: wygląda jak adres, więc nie traktujemy tego jako domeny
		return "", "", fmt.Errorf("niepoprawny adres IP lub zakres: %q", v)
	}
	if domainRe.MatchString(d) {
		return d, KindDomain, nil
	}
	return "", "", fmt.Errorf("nierozpoznany cel: %q", v)
}

// ParseText: jeden cel na linię albo rozdzielone przecinkami/spacjami (formularz ręczny).
func ParseText(s string) ([]Input, []string) {
	var out []Input
	var errs []string
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' }) {
		if strings.HasPrefix(tok, "#") {
			continue
		}
		out = append(out, Input{Value: tok})
	}
	return out, errs
}

// ParseCSV: kolumny value/target/ip/cidr/domain/host (pierwsza pasująca), tags (rozdzielone | lub ;), note.
// Bez nagłówka: pierwsza kolumna to cel.
func ParseCSV(r io.Reader) ([]Input, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return nil, err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	cr := csv.NewReader(bytes.NewReader(data))
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	if bytes.Count(data[:min(len(data), 2048)], []byte(";")) > bytes.Count(data[:min(len(data), 2048)], []byte(",")) {
		cr.Comma = ';'
	}
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	col := map[string]int{}
	header := false
	for i, h := range rows[0] {
		h = strings.ToLower(strings.TrimSpace(h))
		col[h] = i
		switch h {
		case "value", "target", "ip", "cidr", "domain", "host", "address", "adres", "cel":
			header = true
		}
	}
	vi := 0
	if header {
		for _, k := range []string{"value", "target", "ip", "address", "adres", "cel", "cidr", "domain", "host"} {
			if i, ok := col[k]; ok {
				vi = i
				break
			}
		}
		rows = rows[1:]
	}
	ti, hasT := col["tags"]
	ni, hasN := col["note"]
	var out []Input
	for _, r := range rows {
		if len(r) <= vi || strings.TrimSpace(r[vi]) == "" {
			continue
		}
		in := Input{Value: strings.TrimSpace(r[vi])}
		if header && hasT && len(r) > ti {
			in.Tags = splitTags(r[ti])
		}
		if header && hasN && len(r) > ni {
			in.Note = strings.TrimSpace(r[ni])
		}
		out = append(out, in)
	}
	return out, nil
}

// ParseJSON: ["10.0.0.1", ...] albo [{"value": "...", "tags": [...], "note": "..."}] albo {"targets": [...]}.
func ParseJSON(r io.Reader) ([]Input, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	if len(data) > 0 && data[0] == '{' {
		var wrap struct {
			Targets json.RawMessage `json:"targets"`
		}
		if err := json.Unmarshal(data, &wrap); err != nil {
			return nil, err
		}
		data = wrap.Targets
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("oczekiwano tablicy celów: %w", err)
	}
	var out []Input
	for _, m := range raw {
		var s string
		if json.Unmarshal(m, &s) == nil {
			out = append(out, Input{Value: s})
			continue
		}
		var obj struct {
			Value  string `json:"value"`
			Target string `json:"target"`
			IP     string `json:"ip"`
			Tags   any    `json:"tags"`
			Note   string `json:"note"`
		}
		if err := json.Unmarshal(m, &obj); err != nil {
			return nil, err
		}
		v := firstNonEmpty(obj.Value, obj.Target, obj.IP)
		in := Input{Value: v, Note: obj.Note}
		switch t := obj.Tags.(type) {
		case string:
			in.Tags = splitTags(t)
		case []any:
			for _, x := range t {
				if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
					in.Tags = append(in.Tags, strings.TrimSpace(s))
				}
			}
		}
		out = append(out, in)
	}
	return out, nil
}

func splitTags(s string) []string {
	var out []string
	for _, t := range strings.FieldsFunc(s, func(r rune) bool { return r == '|' || r == ';' || r == ',' }) {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// ---- rozwijanie celów ----

// Expanded: lista adresów do skanu + mapowanie IP → nazwy domenowe (do nagłówka Host).
type Expanded struct {
	IPs       []netip.Addr
	Hostnames map[string][]string
	Errors    []string
}

type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Expand rozwija cele; domeny rozwiązywane przez DNS. Adresy z excludes są pomijane.
func Expand(ctx context.Context, values []string, excludes []netip.Prefix, res Resolver) (*Expanded, error) {
	if res == nil {
		res = net.DefaultResolver
	}
	seen := map[netip.Addr]bool{}
	ex := &Expanded{Hostnames: map[string][]string{}}
	add := func(a netip.Addr) error {
		a = a.Unmap()
		for _, p := range excludes {
			if p.Contains(a) {
				return nil
			}
		}
		if !seen[a] {
			if len(seen) >= MaxExpand {
				return fmt.Errorf("przekroczono limit %d adresów w jednym skanie", MaxExpand)
			}
			seen[a] = true
			ex.IPs = append(ex.IPs, a)
		}
		return nil
	}
	for _, v := range values {
		norm, kind, err := Classify(v)
		if err != nil {
			ex.Errors = append(ex.Errors, err.Error())
			continue
		}
		switch kind {
		case KindIP:
			if err := add(netip.MustParseAddr(norm)); err != nil {
				return nil, err
			}
		case KindCIDR:
			p := netip.MustParsePrefix(norm)
			if p.Addr().Is4() && p.Bits() <= 30 {
				// pomijamy adres sieci i broadcast dla /30 i większych
				first := p.Addr().Next()
				last := lastAddr(p)
				for a := first; a.Less(last) && p.Contains(a); a = a.Next() {
					if err := add(a); err != nil {
						return nil, err
					}
				}
			} else {
				for a := p.Addr(); p.Contains(a); a = a.Next() {
					if err := add(a); err != nil {
						return nil, err
					}
					if !a.Next().IsValid() {
						break
					}
				}
			}
		case KindRange:
			parts := strings.SplitN(norm, "-", 2)
			a, b := netip.MustParseAddr(parts[0]), netip.MustParseAddr(parts[1])
			for x := a; !b.Less(x); x = x.Next() {
				if err := add(x); err != nil {
					return nil, err
				}
				if x == b {
					break
				}
			}
		case KindDomain:
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			addrs, err := res.LookupHost(cctx, norm)
			cancel()
			if err != nil {
				ex.Errors = append(ex.Errors, fmt.Sprintf("DNS %s: %v", norm, err))
				continue
			}
			for _, s := range addrs {
				a, err := netip.ParseAddr(s)
				if err != nil || !a.Is4() {
					continue // skan IPv6 poza zakresem prototypu
				}
				if err := add(a); err != nil {
					return nil, err
				}
				k := a.Unmap().String()
				ex.Hostnames[k] = appendUniq(ex.Hostnames[k], norm)
			}
		}
	}
	sort.Slice(ex.IPs, func(i, j int) bool { return ex.IPs[i].Less(ex.IPs[j]) })
	return ex, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n |= (1 << (32 - p.Bits())) - 1
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// CountEstimate: szybka liczba adresów bez rozwijania (do walidacji formularza i ETA).
func CountEstimate(values []string) int {
	n := 0
	for _, v := range values {
		norm, kind, err := Classify(v)
		if err != nil {
			continue
		}
		switch kind {
		case KindIP, KindDomain:
			n++
		case KindCIDR:
			p := netip.MustParsePrefix(norm)
			if p.Addr().Is4() {
				c := 1 << (32 - p.Bits())
				if p.Bits() <= 30 {
					c -= 2
				}
				n += c
			} else {
				n += 1 << (128 - p.Bits())
			}
		case KindRange:
			parts := strings.SplitN(norm, "-", 2)
			a, b := netip.MustParseAddr(parts[0]).As4(), netip.MustParseAddr(parts[1]).As4()
			ai := int(a[0])<<24 | int(a[1])<<16 | int(a[2])<<8 | int(a[3])
			bi := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
			n += bi - ai + 1
		}
	}
	return n
}
