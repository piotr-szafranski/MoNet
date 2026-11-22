package sig

// Import sygnatur z plików w różnych formatach. Format nie jest znany z góry (AGH przygotuje własny zestaw),
// dlatego rozpoznajemy i konwertujemy najpopularniejsze: format MoNet (YAML/JSON), szablony nuclei (tylko bezpieczne
// zapytania GET bez payloadów), format Wappalyzera (technologies.json) i prosty CSV. Każda sygnatura jest
// kompilowana i walidowana; elementy nieobsługiwane trafiają do ostrzeżeń zamiast przerywać import.

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type ImportResult struct {
	Format     string      `json:"format"`
	Signatures []Signature `json:"signatures"`
	Warnings   []string    `json:"warnings"`
	Skipped    int         `json:"skipped"`
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	repl := strings.NewReplacer("ą", "a", "ć", "c", "ę", "e", "ł", "l", "ń", "n", "ó", "o", "ś", "s", "ź", "z", "ż", "z")
	s = slugRe.ReplaceAllString(repl.Replace(s), "-")
	return strings.Trim(s, "-")
}

// Convert rozpoznaje format i zwraca skompilowane sygnatury.
func Convert(data []byte, filename string) (*ImportResult, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	t := bytes.TrimSpace(data)
	if len(t) == 0 {
		return nil, fmt.Errorf("pusty plik")
	}
	low := strings.ToLower(filename)
	switch {
	case t[0] == '{' || t[0] == '[':
		return convertJSON(t)
	case strings.HasSuffix(low, ".csv"):
		return convertCSV(t)
	default:
		return convertYAML(t)
	}
}

func (r *ImportResult) add(s Signature) {
	if err := s.Compile(); err != nil {
		r.Warnings = append(r.Warnings, err.Error())
		r.Skipped++
		return
	}
	r.Signatures = append(r.Signatures, s)
}

// ---- JSON: MoNet, {"signatures": [...]}, Wappalyzer ----

func convertJSON(t []byte) (*ImportResult, error) {
	if t[0] == '[' {
		var list []Signature
		if err := json.Unmarshal(t, &list); err != nil {
			return nil, fmt.Errorf("JSON: %w", err)
		}
		r := &ImportResult{Format: "asi-json"}
		for _, s := range list {
			r.add(s)
		}
		return r, nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(t, &top); err != nil {
		return nil, fmt.Errorf("JSON: %w", err)
	}
	if raw, ok := top["signatures"]; ok {
		return convertJSON(raw)
	}
	if raw, ok := top["technologies"]; ok {
		return convertWappalyzer(raw)
	}
	// sam słownik technologii (plik w stylu technologies/a.json)
	return convertWappalyzer(t)
}

var wapCats = map[int]string{1: "cms", 6: "cms", 11: "cms", 18: "framework", 22: "server", 27: "language", 31: "proxy", 64: "proxy",
	34: "database", 47: "devops", 44: "devops", 46: "admin-panel", 9: "admin-panel", 39: "iot", 16: "security"}

// Wappalyzer: wzorce mają postać "regex\;version:\1\;confidence:50".
func wapPattern(p string) (re string, version bool, conf float64) {
	parts := strings.Split(p, "\\;")
	re, conf = parts[0], 0
	for _, x := range parts[1:] {
		switch {
		case strings.HasPrefix(x, "version:"):
			version = strings.Contains(x, "\\1")
		case strings.HasPrefix(x, "confidence:"):
			if v, err := strconv.Atoi(strings.TrimPrefix(x, "confidence:")); err == nil {
				conf = float64(v) / 100
			}
		}
	}
	if version {
		// pierwsza grupa przechwytująca (nie „(?”, nie poprzedzona „\”) staje się grupą wersji
		for i := 0; i < len(re); i++ {
			if re[i] == '\\' {
				i++
				continue
			}
			if re[i] == '(' && (i+1 >= len(re) || re[i+1] != '?') {
				re = re[:i] + "(?P<version>" + re[i+1:]
				break
			}
		}
	}
	return re, version, conf
}

// inner: wzorzec osadzany w większym wyrażeniu traci kotwice ^ i $.
func inner(re string) string { return strings.TrimSuffix(strings.TrimPrefix(re, "^"), "$") }

func strList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func convertWappalyzer(raw []byte) (*ImportResult, error) {
	var techs map[string]map[string]any
	if err := json.Unmarshal(raw, &techs); err != nil {
		return nil, fmt.Errorf("nierozpoznany format JSON (ani MoNet, ani Wappalyzer): %w", err)
	}
	r := &ImportResult{Format: "wappalyzer"}
	names := make([]string, 0, len(techs))
	for n := range techs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		def := techs[name]
		s := Signature{ID: "wap-" + slug(name), Name: name, Category: "other", Interest: 5, Match: "any"}
		if cats, ok := def["cats"].([]any); ok {
			for _, c := range cats {
				if f, ok := c.(float64); ok {
					if cat, ok := wapCats[int(f)]; ok {
						s.Category = cat
						break
					}
				}
			}
		}
		addM := func(m Matcher, w float64) {
			if w == 0 {
				w = 0.6
			}
			m.Weight = w
			if m.Regex != "" {
				if _, err := regexp.Compile("(?i)" + m.Regex); err != nil {
					r.Warnings = append(r.Warnings, fmt.Sprintf("%s: pominięto wzorzec %q (składnia nieobsługiwana w RE2)", name, m.Regex))
					return
				}
			}
			s.Matchers = append(s.Matchers, m)
		}
		if h, ok := def["headers"].(map[string]any); ok {
			for hn, hv := range h {
				re, _, c := wapPattern(fmt.Sprint(hv))
				addM(Matcher{Type: "header", Name: hn, Regex: re}, c)
			}
		}
		if ck, ok := def["cookies"].(map[string]any); ok {
			for cn := range ck {
				addM(Matcher{Type: "cookie", Name: "^" + regexp.QuoteMeta(cn) + "$"}, 0)
			}
		}
		for _, key := range []string{"html", "text", "css"} {
			for _, p := range strList(def[key]) {
				re, _, c := wapPattern(p)
				addM(Matcher{Type: "body", Regex: re}, c)
			}
		}
		for _, p := range append(strList(def["scriptSrc"]), strList(def["scripts"])...) {
			re, _, c := wapPattern(p)
			addM(Matcher{Type: "body", Regex: `<script[^>]+src=["'][^"']*` + inner(re)}, c)
		}
		if meta, ok := def["meta"].(map[string]any); ok {
			for mn, mv := range meta {
				for _, p := range strList(mv) {
					re, _, c := wapPattern(p)
					addM(Matcher{Type: "body", Regex: `<meta[^>]+name=["']` + regexp.QuoteMeta(mn) + `["'][^>]+content=["']` + inner(re)}, c)
				}
			}
		}
		for _, p := range strList(def["url"]) {
			re, _, c := wapPattern(p)
			addM(Matcher{Type: "hostname", Regex: re}, c)
		}
		if len(s.Matchers) == 0 {
			r.Skipped++
			continue // technologia wykrywana tylko po JS/DOM (poza zakresem skanera)
		}
		r.add(s)
	}
	return r, nil
}

// ---- YAML: MoNet albo szablony nuclei ----

type nucleiTpl struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string `yaml:"name"`
		Severity string `yaml:"severity"`
		Tags     any    `yaml:"tags"`
	} `yaml:"info"`
	HTTP     []nucleiReq `yaml:"http"`
	Requests []nucleiReq `yaml:"requests"`
}

type nucleiReq struct {
	Method      string          `yaml:"method"`
	Path        []string        `yaml:"path"`
	Raw         []string        `yaml:"raw"`
	Body        string          `yaml:"body"`
	Payloads    map[string]any  `yaml:"payloads"`
	MatchersCnd string          `yaml:"matchers-condition"`
	Matchers    []nucleiMatcher `yaml:"matchers"`
}

type nucleiMatcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Status    []int    `yaml:"status"`
	DSL       []string `yaml:"dsl"`
	Condition string   `yaml:"condition"`
	Negative  bool     `yaml:"negative"`
}

var mmh3Re = regexp.MustCompile(`mmh3\([^)]*\)\)?\s*==\s*['"]?(-?\d+)`)

func convertYAML(t []byte) (*ImportResult, error) {
	// kilka dokumentów YAML (---) albo lista
	dec := yaml.NewDecoder(bytes.NewReader(t))
	var docs []yaml.Node
	for {
		var n yaml.Node
		if err := dec.Decode(&n); err != nil {
			break
		}
		docs = append(docs, n)
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("nie udało się odczytać YAML")
	}
	r := &ImportResult{}
	for _, d := range docs {
		var probe any
		_ = d.Decode(&probe)
		if m, ok := probe.(map[string]any); ok {
			if _, isNuclei := m["info"]; isNuclei {
				var tpl nucleiTpl
				if err := d.Decode(&tpl); err != nil {
					r.Warnings = append(r.Warnings, "szablon nuclei: "+err.Error())
					continue
				}
				r.Format = "nuclei"
				convertNuclei(r, tpl)
				continue
			}
		}
		var list []Signature
		if err := d.Decode(&list); err != nil {
			var one Signature
			if err2 := d.Decode(&one); err2 != nil || one.ID == "" {
				r.Warnings = append(r.Warnings, "nierozpoznany dokument YAML")
				continue
			}
			list = []Signature{one}
		}
		if r.Format == "" {
			r.Format = "asi-yaml"
		}
		for _, s := range list {
			r.add(s)
		}
	}
	if r.Format == "" {
		return nil, fmt.Errorf("nie rozpoznano formatu sygnatur: %s", strings.Join(r.Warnings, "; "))
	}
	return r, nil
}

func convertNuclei(r *ImportResult, tpl nucleiTpl) {
	reqs := append(tpl.HTTP, tpl.Requests...)
	name := tpl.Info.Name
	if name == "" {
		name = tpl.ID
	}
	s := Signature{ID: "nuc-" + slug(tpl.ID), Name: name, Category: nucleiCategory(tpl), Interest: nucleiInterest(tpl.Info.Severity), Match: "any"}
	for _, q := range reqs {
		if len(q.Raw) > 0 || q.Body != "" || len(q.Payloads) > 0 || (q.Method != "" && !strings.EqualFold(q.Method, "GET")) {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: pominięto zapytanie inne niż proste GET (bezpieczeństwo: brak payloadów i metod modyfikujących)", tpl.ID))
			continue
		}
		path := "/"
		for _, p := range q.Path {
			p = strings.ReplaceAll(strings.ReplaceAll(p, "{{BaseURL}}", ""), "{{RootURL}}", "")
			if strings.Contains(p, "{{") {
				r.Warnings = append(r.Warnings, fmt.Sprintf("%s: pominięto ścieżkę ze zmiennymi %q", tpl.ID, p))
				continue
			}
			if p == "" {
				p = "/"
			}
			path = p
			break
		}
		if strings.EqualFold(q.MatchersCnd, "and") {
			s.Match = "all"
		}
		// ścieżka główna: dopasowania do strony głównej; inna ścieżka: matcher path z warunkami
		var status []int
		var res []string
		for _, m := range q.Matchers {
			var pats []string
			switch m.Type {
			case "word":
				for _, w := range m.Words {
					pats = append(pats, regexp.QuoteMeta(w))
				}
			case "regex":
				pats = m.Regex
			case "status":
				status = append(status, m.Status...)
				continue
			case "dsl":
				for _, d := range m.DSL {
					if mm := mmh3Re.FindStringSubmatch(d); mm != nil {
						if h, err := strconv.ParseInt(mm[1], 10, 32); err == nil {
							s.Matchers = append(s.Matchers, Matcher{Type: "favicon", Hashes: []int32{int32(h)}, Weight: 0.9})
						}
					} else {
						r.Warnings = append(r.Warnings, fmt.Sprintf("%s: pominięto wyrażenie dsl %q", tpl.ID, d))
					}
				}
				continue
			default:
				r.Warnings = append(r.Warnings, fmt.Sprintf("%s: nieobsługiwany typ matchera %q", tpl.ID, m.Type))
				continue
			}
			if len(pats) == 0 {
				continue
			}
			joined := strings.Join(pats, "|")
			if strings.EqualFold(m.Condition, "and") && len(pats) > 1 {
				// każde słowo osobno (wszystkie muszą wystąpić)
				for _, p := range pats {
					res = append(res, m.Part+"\x00"+p)
				}
				s.Match = "all"
			} else {
				res = append(res, m.Part+"\x00"+joined)
			}
		}
		for _, x := range res {
			part, pat := strings.SplitN(x, "\x00", 2)[0], strings.SplitN(x, "\x00", 2)[1]
			if path != "/" {
				s.Matchers = append(s.Matchers, Matcher{Type: "path", Path: path, Status: status, Regex: pat, Weight: 0.9})
				continue
			}
			switch strings.ToLower(part) {
			case "header":
				s.Matchers = append(s.Matchers, Matcher{Type: "header", Name: "server", Regex: pat, Weight: 0.7})
				r.Warnings = append(r.Warnings, fmt.Sprintf("%s: dopasowanie do nagłówków przypisano do nagłówka Server", tpl.ID))
			case "title":
				s.Matchers = append(s.Matchers, Matcher{Type: "title", Regex: pat, Weight: 0.8})
			default:
				s.Matchers = append(s.Matchers, Matcher{Type: "body", Regex: pat, Weight: 0.8})
			}
		}
		if len(res) == 0 && len(status) > 0 && path != "/" {
			s.Matchers = append(s.Matchers, Matcher{Type: "path", Path: path, Status: status, Weight: 0.7})
		}
	}
	if len(s.Matchers) == 0 {
		r.Skipped++
		r.Warnings = append(r.Warnings, fmt.Sprintf("%s: brak bezpiecznych matcherów do zaimportowania", tpl.ID))
		return
	}
	r.add(s)
}

func nucleiInterest(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 40
	case "high":
		return 30
	case "medium":
		return 20
	case "low":
		return 10
	}
	return 5
}

func nucleiCategory(t nucleiTpl) string {
	tags := strings.ToLower(fmt.Sprint(t.Info.Tags))
	switch {
	case strings.Contains(tags, "panel") || strings.Contains(tags, "login"):
		return "admin-panel"
	case strings.Contains(tags, "iot"):
		return "iot"
	case strings.Contains(tags, "cms") || strings.Contains(tags, "wordpress"):
		return "cms"
	case strings.Contains(tags, "exposure") || strings.Contains(tags, "config"):
		return "interesting"
	case strings.Contains(tags, "tech"):
		return "server"
	}
	return "other"
}

// ---- CSV: name,type,pattern[,category,interest,name_or_header,path,status,weight] ----

func convertCSV(t []byte) (*ImportResult, error) {
	cr := csv.NewReader(bytes.NewReader(t))
	cr.FieldsPerRecord = -1
	if bytes.Count(t[:min(len(t), 1024)], []byte(";")) > bytes.Count(t[:min(len(t), 1024)], []byte(",")) {
		cr.Comma = ';'
	}
	rows, err := cr.ReadAll()
	if err != nil || len(rows) < 2 {
		return nil, fmt.Errorf("CSV: wymagany nagłówek i co najmniej jeden wiersz")
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	get := func(r []string, ks ...string) string {
		for _, k := range ks {
			if i, ok := col[k]; ok && i < len(r) {
				return strings.TrimSpace(r[i])
			}
		}
		return ""
	}
	if _, ok := col["type"]; !ok {
		return nil, fmt.Errorf("CSV: wymagane kolumny name, type, pattern (opcjonalnie category, interest, header, path, status, weight)")
	}
	bySig := map[string]*Signature{}
	var order []string
	res := &ImportResult{Format: "csv"}
	for _, r := range rows[1:] {
		name := get(r, "name", "nazwa")
		if name == "" {
			continue
		}
		id := get(r, "id")
		if id == "" {
			id = "csv-" + slug(name)
		}
		s := bySig[id]
		if s == nil {
			s = &Signature{ID: id, Name: name, Category: get(r, "category", "kategoria"), Match: "any"}
			s.Interest, _ = strconv.Atoi(get(r, "interest", "waga"))
			bySig[id] = s
			order = append(order, id)
		}
		m := Matcher{Type: strings.ToLower(get(r, "type", "typ")), Regex: get(r, "pattern", "regex", "wzorzec"), Name: get(r, "header", "name_field", "cookie"), Path: get(r, "path", "sciezka")}
		if m.Type == "cookie" && m.Name == "" {
			m.Name, m.Regex = m.Regex, ""
		}
		if m.Type == "favicon" {
			if h, err := strconv.ParseInt(m.Regex, 10, 32); err == nil {
				m.Hashes, m.Regex = []int32{int32(h)}, ""
			}
		}
		for _, st := range strings.FieldsFunc(get(r, "status"), func(c rune) bool { return c == '|' || c == ' ' }) {
			if v, err := strconv.Atoi(st); err == nil {
				m.Status = append(m.Status, v)
			}
		}
		m.Weight, _ = strconv.ParseFloat(get(r, "weight"), 64)
		s.Matchers = append(s.Matchers, m)
	}
	for _, id := range order {
		res.add(*bySig[id])
	}
	return res, nil
}
