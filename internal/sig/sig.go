// Package sig: bezpieczne sygnatury detekcyjne (YAML). Wykrywają obecność cech/komponentów,
// nigdy nie eksploatują: tylko dopasowania do już pobranej odpowiedzi i GET na wskazane ścieżki.
package sig

import (
	_ "embed"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed builtin.yaml
var BuiltinYAML []byte

type Matcher struct {
	Type   string  `yaml:"type" json:"type"`                       // header|cookie|body|title|favicon|path|banner|service|cert|hostname|status|port
	Name   string  `yaml:"name,omitempty" json:"name,omitempty"`   // nazwa nagłówka / regex nazwy ciasteczka
	Regex  string  `yaml:"regex,omitempty" json:"regex,omitempty"` // regex wartości; grupa (?P<version>...) wyciąga wersję
	Path   string  `yaml:"path,omitempty" json:"path,omitempty"`   // dla type=path
	Status []int   `yaml:"status,omitempty" json:"status,omitempty"`
	Hashes []int32 `yaml:"hashes,omitempty" json:"hashes,omitempty"` // favicon mmh3 (format Shodan)
	Ports  []int   `yaml:"ports,omitempty" json:"ports,omitempty"`
	Weight float64 `yaml:"weight,omitempty" json:"weight,omitempty"`
	Negate bool    `yaml:"negate,omitempty" json:"negate,omitempty"`
	re     *regexp.Regexp
	nameRe *regexp.Regexp
}

type Signature struct {
	ID            string    `yaml:"id" json:"id"`
	Name          string    `yaml:"name" json:"name"`
	Category      string    `yaml:"category" json:"category"` // cms|framework|server|appserver|iot|admin-panel|staging|devops|database|interesting|security
	Description   string    `yaml:"description,omitempty" json:"description,omitempty"`
	Interest      int       `yaml:"interest,omitempty" json:"interest,omitempty"`
	Match         string    `yaml:"match,omitempty" json:"match,omitempty"` // any (domyślnie) | all
	MinConfidence int       `yaml:"min_confidence,omitempty" json:"min_confidence,omitempty"`
	Tags          []string  `yaml:"tags,omitempty" json:"tags,omitempty"`
	Matchers      []Matcher `yaml:"matchers" json:"matchers"`
}

// Detection: wynik dopasowania sygnatury z poziomem pewności i dowodami.
type Detection struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Version    string   `json:"version,omitempty"`
	Confidence int      `json:"confidence"`
	Interest   int      `json:"interest"`
	Evidence   []string `json:"evidence"`
}

// Input: wszystko, co wiemy o usłudze (z nmapa i sondy HTTP). Sygnatury działają tylko na tych danych.
type Input struct {
	Port     int
	Service  string
	Banner   string // product + version + extrainfo z nmapa
	Hostname string
	Status   int
	Title    string
	Headers  map[string][]string // klucze lowercase
	Cookies  []string            // nazwy ciasteczek
	Body     string
	FavHash  *int32
	CertText string                  // subject/issuer/SAN
	PathHits map[string]PathResponse // GET na ścieżki z sygnatur
}

type PathResponse struct {
	Status int
	Body   string
	Title  string
}

// Ścieżki w sygnaturach: biała lista zamiast listy zakazanych nazw. Parametry zapytania tylko z krótkiej listy
// neutralnych nazw i z krótkimi wartościami; żadnych parametrów macierzowych (;jsessionid) ani segmentów
// wyglądających jak para login/hasło (np. /login/admin/admin).
var safeParams = map[string]bool{"format": true, "output": true, "lang": true, "v": true, "version": true, "page": true, "view": true, "mode": true}
var safeValue = regexp.MustCompile(`^[A-Za-z0-9._\-]{0,32}$`)
var credWords = map[string]bool{"admin": true, "root": true, "user": true, "test": true, "guest": true, "password": true, "pass": true,
	"administrator": true, "default": true, "123456": true, "12345": true, "changeme": true, "toor": true, "demo": true}

// credLike: słowo z listy albo słowo z listy z doklejonymi cyframi/znakami (admin123, root!).
func credLike(x string) bool {
	for w := range credWords {
		if x == w || (strings.HasPrefix(x, w) && strings.Trim(x[len(w):], "0123456789!@#$_.-") == "") {
			return true
		}
	}
	return false
}

func safePath(p string) error {
	if strings.Contains(p, ";") {
		return fmt.Errorf("ścieżka nie może zawierać parametrów po „;”")
	}
	path, query, _ := strings.Cut(p, "?")
	if query != "" {
		for _, kv := range strings.Split(query, "&") {
			k, v, _ := strings.Cut(kv, "=")
			if !safeParams[strings.ToLower(k)] || !safeValue.MatchString(v) {
				return fmt.Errorf("parametr %q niedozwolony (dozwolone: format, output, lang, v, version, page, view, mode z krótką wartością)", k)
			}
		}
	}
	if dec, err := url.PathUnescape(path); err == nil {
		path = dec // /%61dmin to /admin
	}
	seg := strings.Split(strings.Trim(strings.ToLower(path), "/"), "/")
	for i := 1; i < len(seg); i++ {
		if credWords[seg[i-1]] && credLike(seg[i]) {
			return fmt.Errorf("segmenty %q/%q wyglądają na parę login/hasło", seg[i-1], seg[i])
		}
	}
	return nil
}

func validCategory(c string) bool {
	switch c {
	case "cms", "framework", "server", "appserver", "iot", "admin-panel", "staging", "devops", "database",
		"interesting", "security", "proxy", "language", "other":
		return true
	}
	return false
}

// Compile sprawdza poprawność sygnatury (używane też przy zapisie z UI).
func (s *Signature) Compile() error {
	if strings.TrimSpace(s.ID) == "" || strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("sygnatura musi mieć id i name")
	}
	if s.Category == "" {
		s.Category = "other"
	}
	if !validCategory(s.Category) {
		return fmt.Errorf("%s: nieznana kategoria %q", s.ID, s.Category)
	}
	if s.Match == "" {
		s.Match = "any"
	}
	if len(s.Matchers) == 0 {
		return fmt.Errorf("%s: brak matcherów", s.ID)
	}
	for i := range s.Matchers {
		m := &s.Matchers[i]
		m.Type = strings.ToLower(m.Type)
		if m.Weight == 0 {
			m.Weight = 0.5
		}
		switch m.Type {
		case "header", "cookie", "body", "title", "favicon", "path", "banner", "service", "cert", "hostname", "status", "port":
		default:
			return fmt.Errorf("%s: nieznany typ matchera %q", s.ID, m.Type)
		}
		if m.Type == "path" {
			if !strings.HasPrefix(m.Path, "/") || strings.ContainsAny(m.Path, " \r\n") || len(m.Path) > 200 {
				return fmt.Errorf("%s: ścieżka musi zaczynać się od / i nie zawierać spacji", s.ID)
			}
			if err := safePath(m.Path); err != nil {
				return fmt.Errorf("%s: %v; sygnatury tylko odczytują odpowiedzi, bez logowania", s.ID, err)
			}
		}
		if m.Type == "header" && m.Name == "" {
			return fmt.Errorf("%s: matcher header wymaga name", s.ID)
		}
		if m.Regex != "" {
			re, err := regexp.Compile("(?i)" + m.Regex)
			if err != nil {
				return fmt.Errorf("%s: regex %q: %v", s.ID, m.Regex, err)
			}
			m.re = re
		}
		if m.Type == "cookie" && m.Name != "" {
			re, err := regexp.Compile("(?i)" + m.Name)
			if err != nil {
				return fmt.Errorf("%s: regex nazwy ciasteczka: %v", s.ID, err)
			}
			m.nameRe = re
		}
		m.Name = strings.ToLower(m.Name)
	}
	return nil
}

func ParseYAML(b []byte) ([]Signature, error) {
	var list []Signature
	if err := yaml.Unmarshal(b, &list); err != nil {
		var one Signature
		if err2 := yaml.Unmarshal(b, &one); err2 != nil || one.ID == "" {
			return nil, err
		}
		list = []Signature{one}
	}
	for i := range list {
		if err := list[i].Compile(); err != nil {
			return nil, err
		}
	}
	return list, nil
}

// Engine: zestaw skompilowanych sygnatur, bezpieczny współbieżnie.
type Engine struct {
	mu   sync.RWMutex
	sigs []Signature
}

func NewEngine(sigs []Signature) *Engine { return &Engine{sigs: sigs} }

func (e *Engine) Set(sigs []Signature) {
	e.mu.Lock()
	e.sigs = sigs
	e.mu.Unlock()
}

func (e *Engine) All() []Signature {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Signature(nil), e.sigs...)
}

// Paths: unikalne ścieżki do pobrania (GET, bez logowania), posortowane, z limitem.
func (e *Engine) Paths(limit int) []string {
	set := map[string]bool{}
	for _, s := range e.All() {
		for _, m := range s.Matchers {
			if m.Type == "path" {
				set[m.Path] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// PathsFor: ścieżki warte sprawdzenia dla tej usługi. Sygnatury złożone wyłącznie z matcherów path są ogólne
// (zawsze); pozostałe sprawdzają ścieżkę tylko, gdy strona główna już częściowo pasuje (potwierdzenie).
func (e *Engine) PathsFor(in Input, limit int, generic bool) []string {
	set := map[string]bool{}
	var out []string
	for _, s := range e.All() {
		var paths []string
		other, hit := 0, false
		for i := range s.Matchers {
			m := &s.Matchers[i]
			if m.Type == "path" {
				paths = append(paths, m.Path)
				continue
			}
			other++
			if !hit {
				if ok, _, _ := m.match(in); ok != m.Negate {
					hit = true
				}
			}
		}
		if len(paths) == 0 || (other > 0 && !hit) || (other == 0 && !generic) {
			continue
		}
		for _, p := range paths {
			if !set[p] {
				set[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (e *Engine) Evaluate(in Input) []Detection {
	var out []Detection
	for _, s := range e.All() {
		if d, ok := Eval(&s, in); ok {
			out = append(out, d)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Eval: dopasowanie jednej sygnatury. Pewność = suma wag dopasowanych matcherów (max 100%).
func Eval(s *Signature, in Input) (Detection, bool) {
	d := Detection{ID: s.ID, Name: s.Name, Category: s.Category, Interest: s.Interest}
	var score float64
	matched := 0
	for i := range s.Matchers {
		m := &s.Matchers[i]
		ok, ev, ver := m.match(in)
		if m.Negate {
			ok = !ok
			ev = "brak: " + m.Type + " " + m.Name + m.Path
		}
		if ok {
			matched++
			score += m.Weight
			d.Evidence = append(d.Evidence, ev)
			if ver != "" && d.Version == "" {
				d.Version = ver
			}
		} else if s.Match == "all" {
			return d, false
		}
	}
	if matched == 0 {
		return d, false
	}
	d.Confidence = int(min(score, 1.0)*100 + 0.5)
	if s.MinConfidence > 0 && d.Confidence < s.MinConfidence {
		return d, false
	}
	return d, true
}

func (m *Matcher) find(s string) (bool, string) {
	if m.re == nil {
		return s != "", ""
	}
	sm := m.re.FindStringSubmatch(s)
	if sm == nil {
		return false, ""
	}
	ver := ""
	for i, n := range m.re.SubexpNames() {
		if n == "version" && i < len(sm) {
			ver = sm[i]
		}
	}
	return true, ver
}

func short(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

func (m *Matcher) match(in Input) (bool, string, string) {
	switch m.Type {
	case "header":
		for _, v := range in.Headers[m.Name] {
			if ok, ver := m.find(v); ok {
				return true, "nagłówek " + m.Name + ": " + short(v), ver
			}
		}
	case "cookie":
		for _, c := range in.Cookies {
			if m.nameRe != nil && m.nameRe.MatchString(c) {
				return true, "ciasteczko " + c, ""
			}
		}
	case "body":
		if ok, ver := m.find(in.Body); ok && m.re != nil {
			return true, "HTML: /" + short(m.re.String()[4:]) + "/", ver
		}
	case "title":
		if ok, ver := m.find(in.Title); ok && in.Title != "" {
			return true, "tytuł: " + short(in.Title), ver
		}
	case "favicon":
		if in.FavHash != nil {
			for _, h := range m.Hashes {
				if h == *in.FavHash {
					return true, "favicon mmh3 " + strconv.Itoa(int(h)), ""
				}
			}
		}
	case "path":
		pr, ok := in.PathHits[m.Path]
		if !ok || pr.Status == 0 {
			return false, "", ""
		}
		if len(m.Status) > 0 && !containsInt(m.Status, pr.Status) {
			return false, "", ""
		}
		if len(m.Status) == 0 && (pr.Status >= 400 || pr.Status == 0) {
			return false, "", ""
		}
		if m.re != nil {
			if ok, ver := m.find(pr.Body + "\n" + pr.Title); ok {
				return true, fmt.Sprintf("ścieżka %s → %d", m.Path, pr.Status), ver
			}
			return false, "", ""
		}
		return true, fmt.Sprintf("ścieżka %s → %d", m.Path, pr.Status), ""
	case "banner":
		if ok, ver := m.find(in.Banner); ok && in.Banner != "" {
			return true, "baner: " + short(in.Banner), ver
		}
	case "service":
		if ok, _ := m.find(in.Service); ok && in.Service != "" {
			return true, "usługa: " + in.Service, ""
		}
	case "cert":
		if ok, ver := m.find(in.CertText); ok && in.CertText != "" {
			return true, "certyfikat: " + short(in.CertText), ver
		}
	case "hostname":
		if ok, _ := m.find(in.Hostname); ok && in.Hostname != "" {
			return true, "nazwa hosta: " + in.Hostname, ""
		}
	case "status":
		if containsInt(m.Status, in.Status) {
			return true, "kod HTTP " + strconv.Itoa(in.Status), ""
		}
	case "port":
		if containsInt(m.Ports, in.Port) {
			return true, "port " + strconv.Itoa(in.Port), ""
		}
	}
	return false, "", ""
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
