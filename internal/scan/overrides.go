package scan

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/asi-agh/asi/internal/sig"
	"sort"
	"strings"
)

// Override: poprawka analityka dla usługi (ip:port/proto), zapisana w annotations.tech_override jako JSON.
// Nakładana na każdą nową obserwację tej usługi, więc edycja przetrwa kolejne skany (wymaganie 14 briefu).
type Override struct {
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	Interest *int   `json:"interest,omitempty"`
	Techs    []Tech `json:"techs,omitempty"`
	Note     string `json:"note,omitempty"`
	By       string `json:"by,omitempty"`
	// wartości wykryte przez skaner w chwili poprawki: jeśli skaner zobaczy coś innego (np. nową wersję),
	// poprawka produktu/wersji przestaje obowiązywać, żeby nie ukrywać prawdziwej zmiany w porównaniu skanów
	BaseService string   `json:"base_service,omitempty"`
	BaseProduct string   `json:"base_product,omitempty"`
	BaseVersion string   `json:"base_version,omitempty"`
	HasBase     bool     `json:"has_base,omitempty"`
	BaseTechs   []string `json:"base_techs,omitempty"` // ID technologii wykrytych w chwili poprawki technologii
	// Snap: rekord skanera sprzed pierwszej edycji (wykrycia, dowody, fingerprint, klasa). „Cofnij poprawkę”
	// przywraca go 1:1; przeliczanie sygnatur nie jest możliwe, bo treści stron nie są przechowywane w bazie.
	Snap *Observation `json:"snap,omitempty"`
}

// TechIDs: posortowane ID technologii (porównanie stanu wykrytego ze stanem z chwili poprawki).
func TechIDs(ts []Tech) []string {
	out := []string{}
	for _, t := range ts {
		out = append(out, t.ID+"@"+t.Version)
	}
	sort.Strings(out)
	return out
}

// TechsStale: skaner wykrywa inny zestaw technologii niż w chwili poprawki.
func (ov Override) TechsStale(o *Observation) bool {
	return ov.BaseTechs != nil && strings.Join(TechIDs(o.Techs), ",") != strings.Join(ov.BaseTechs, ",")
}

// Stale: skaner widzi inną usługę/produkt/wersję niż w chwili poprawki.
func (ov Override) Stale(o *Observation) bool {
	return ov.HasBase && (o.Service != ov.BaseService || o.Product != ov.BaseProduct || o.Version != ov.BaseVersion)
}

func (o Override) Empty() bool {
	return o.Service == "" && o.Product == "" && o.Version == "" && o.Interest == nil && o.Techs == nil && o.Note == ""
}

// SvcEntity: klucz usługi w tabeli annotations.
func SvcEntity(ip string, port int, proto string) string {
	return fmt.Sprintf("svc:%s:%d/%s", ip, port, proto)
}

type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// Opener: odszyfrowanie pola (secure.Box); nil = pole jawne (testy, dane sprzed szyfrowania).
var Opener func(string) string

// LoadOverrides: wszystkie poprawki analityków i zbiór usług oznaczonych jako fałszywy alarm.
func LoadOverrides(db querier) (map[string]Override, map[string]bool) {
	ov, fp := map[string]Override{}, map[string]bool{}
	rows, err := db.Query(`SELECT entity, COALESCE(tech_override,''), false_positive, COALESCE(updated_by,'') FROM annotations WHERE entity LIKE 'svc:%'`)
	if err != nil {
		return ov, fp
	}
	defer rows.Close()
	for rows.Next() {
		var ent, js, by string
		var f int
		if rows.Scan(&ent, &js, &f, &by) != nil {
			continue
		}
		if f == 1 {
			fp[ent] = true
		}
		if js != "" && !strings.HasPrefix(strings.TrimSpace(js), "{") && Opener != nil {
			js = Opener(js)
		}
		if strings.HasPrefix(strings.TrimSpace(js), "{") {
			var o Override
			if json.Unmarshal([]byte(js), &o) == nil && !o.Empty() {
				if o.By == "" {
					o.By = by
				}
				ov[ent] = o
			}
		}
	}
	return ov, fp
}

// Apply: nakłada poprawkę na obserwację (po ocenie klasy, przed zapisem).
func (ov Override) Apply(o *Observation) {
	marks := ""
	defer func() {
		if marks != "" { // znacznik zawsze po notatce analityka, żeby nie zginął
			o.Data.Note = strings.TrimSpace(o.Data.Note + marks)
		}
	}()
	if ov.Techs != nil && ov.TechsStale(o) {
		ov.Techs = nil // nowy zestaw technologii od skanera: zmiana ma być widoczna w porównaniu skanów
		marks += " [skaner wykrył inne technologie niż w poprawce analityka]"
	}
	if ov.Stale(o) {
		// nowa wersja/produkt: zostaje wynik skanera (widoczny w porównaniu); klasa, technologie i notatka nadal obowiązują
		ov.Service, ov.Product, ov.Version = "", "", ""
		marks += " [skaner wykrył zmianę względem poprawki analityka]"
	}
	if ov.Service != "" {
		o.Service = ov.Service
	}
	if ov.Product != "" {
		o.Product, o.Data.Banner.Product = ov.Product, ov.Product
	}
	if ov.Version != "" {
		o.Version, o.Data.Banner.Version = ov.Version, ov.Version
	}
	if ov.Techs != nil {
		o.Techs = append([]Tech{}, ov.Techs...)
		o.Data.Detections = nil
		for _, t := range ov.Techs {
			o.Data.Detections = append(o.Data.Detections, sig.Detection{ID: t.ID, Name: t.Name, Category: t.Category, Version: t.Version,
				Confidence: t.Confidence, Evidence: []string{"poprawka analityka"}})
		}
	}
	if ov.Note != "" {
		o.Data.Note = ov.Note
	}
	if ov.Interest != nil {
		o.Interest = max(0, min(100, *ov.Interest))
	}
	o.Edited, o.EditedBy = true, ov.By
	o.Fingerprint = o.ComputeFingerprint()
}

// ApplyOverrides: nakłada poprawki na listę obserwacji (wołane przy zapisie skanu, doskanowania i importu).
func ApplyOverrides(db querier, obs []*Observation) {
	ov, _ := LoadOverrides(db)
	if len(ov) == 0 {
		return
	}
	for _, o := range obs {
		if x, ok := ov[SvcEntity(o.IP, o.Port, o.Proto)]; ok {
			x.Apply(o)
		}
	}
}

// WithoutFalsePositives: usługi oznaczone przez analityka jako fałszywy alarm nie trafiają do DefectDojo.
func WithoutFalsePositives(db querier, obs []*Observation) []*Observation {
	_, fp := LoadOverrides(db)
	if len(fp) == 0 {
		return obs
	}
	out := obs[:0:0]
	for _, o := range obs {
		if !fp[SvcEntity(o.IP, o.Port, o.Proto)] {
			out = append(out, o)
		}
	}
	return out
}
