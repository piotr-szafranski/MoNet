package scan

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// Policy: twarde granice ustawiane przez administratora (Administracja → Polityka skanera). Operator nie może
// ich przekroczyć w konfiguracji skanu, a silnik sprawdza je ponownie przy każdym starcie i wznowieniu.
type Policy struct {
	AllowCIDRs []string `json:"allow_cidrs"`  // pusta lista = bez ograniczenia sieci
	MaxRate    int      `json:"max_rate"`     // pakiety/s nmapa (0 = bez limitu)
	MaxHTTPRPS int      `json:"max_http_rps"` // zapytania HTTP/s
	MaxWorkers int      `json:"max_workers"`  // równoległe podgrupy
	// NoGenericPaths: nie odpytywać ścieżek ogólnych (/admin, /.env, /.git/HEAD, /server-status…) na każdej usłudze HTTP;
	// zostają tylko ścieżki potwierdzające technologię wskazaną już przez stronę główną.
	NoGenericPaths bool `json:"no_generic_paths"`
	Default        bool `json:"default"` // polityka domyślna (administrator jeszcze jej nie zapisał)
}

// DefaultPolicy: bezpieczny stan wyjściowy: tylko sieci prywatne (RFC 1918, CGNAT) i umiarkowane limity.
// Adresy publiczne wymagają świadomej decyzji administratora (zgoda właściciela sieci).
func DefaultPolicy() Policy {
	return Policy{AllowCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"},
		MaxRate: 5000, MaxHTTPRPS: 100, MaxWorkers: 8, Default: true}
}

type settingsGetter interface{ GetSetting(string) string }

func LoadPolicy(s settingsGetter) Policy {
	raw := s.GetSetting("scan_policy")
	if raw == "" {
		return DefaultPolicy()
	}
	var p Policy
	_ = json.Unmarshal([]byte(raw), &p)
	p.Default = false
	return p
}

// Normalize: sprawdza i porządkuje listę sieci.
func (p *Policy) Normalize() error {
	var out []string
	for _, c := range p.AllowCIDRs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		pf, err := netip.ParsePrefix(c)
		if err != nil {
			a, err2 := netip.ParseAddr(c)
			if err2 != nil {
				return fmt.Errorf("niepoprawna sieć: %q", c)
			}
			pf = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, pf.Masked().String())
	}
	p.AllowCIDRs = out
	p.MaxRate, p.MaxHTTPRPS, p.MaxWorkers = max(0, p.MaxRate), max(0, p.MaxHTTPRPS), max(0, p.MaxWorkers)
	return nil
}

// Clamp: obcina parametry konfiguracji do limitów; zwraca listę zmian (do komunikatu dla użytkownika).
func (p Policy) Clamp(c *Config) []string {
	var ch []string
	lim := func(v *int, m int, name string) {
		if m > 0 && *v > m {
			ch = append(ch, fmt.Sprintf("%s %d → %d", name, *v, m))
			*v = m
		}
	}
	lim(&c.Rate, p.MaxRate, "tempo pakietów")
	lim(&c.HTTPRPS, p.MaxHTTPRPS, "zapytania HTTP/s")
	lim(&c.Workers, p.MaxWorkers, "równoległe podgrupy")
	return ch
}

// Allowed: czy adres mieści się w dozwolonych sieciach.
func (p Policy) Allowed(ip string) bool {
	if len(p.AllowCIDRs) == 0 {
		return true
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, c := range p.AllowCIDRs {
		if pf, err := netip.ParsePrefix(c); err == nil && pf.Contains(a) {
			return true
		}
	}
	return false
}

// AllowedTarget: czy cel (IP, CIDR, zakres) w całości mieści się w dozwolonych sieciach. Domeny są sprawdzane
// po rozwiązaniu, przy starcie skanu.
func (p Policy) AllowedTarget(norm, kind string) bool {
	if len(p.AllowCIDRs) == 0 {
		return true
	}
	switch kind {
	case "ip":
		return p.Allowed(norm)
	case "cidr":
		pf, err := netip.ParsePrefix(norm)
		if err != nil {
			return false
		}
		for _, c := range p.AllowCIDRs {
			if ap, err := netip.ParsePrefix(c); err == nil && ap.Bits() <= pf.Bits() && ap.Contains(pf.Addr()) {
				return true
			}
		}
		return false
	case "range":
		a, b, ok := strings.Cut(norm, "-")
		return ok && p.Allowed(a) && p.Allowed(b)
	}
	return true
}

// CheckIPs: błąd z pierwszymi adresami spoza dozwolonych sieci.
func (p Policy) CheckIPs(ips []string) error {
	if len(p.AllowCIDRs) == 0 {
		return nil
	}
	var bad []string
	n := 0
	for _, ip := range ips {
		if ip != "" && !p.Allowed(ip) {
			n++
			if len(bad) < 3 {
				bad = append(bad, ip)
			}
		}
	}
	if n > 0 {
		return fmt.Errorf("%d adresów poza sieciami dozwolonymi przez administratora (np. %s); dozwolone: %s",
			n, strings.Join(bad, ", "), strings.Join(p.AllowCIDRs, ", "))
	}
	return nil
}
