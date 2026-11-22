// Package dojo: eksport wybranych obserwacji do DefectDojo (API v2, import-scan, format „Generic Findings Import”,
// severity Info). Obserwacje trafiają jako findingi informacyjne z dowodami (nagłówki, technologie, certyfikat).
package dojo

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/asi-agh/asi/internal/scan"
)

type Settings struct {
	URL        string `json:"url"`
	Token      string `json:"token,omitempty"`
	Product    string `json:"product"`
	Engagement string `json:"engagement"`
	VerifyTLS  bool   `json:"verify_tls"`
}

type finding struct {
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	Severity       string     `json:"severity"`
	Date           string     `json:"date"`
	Active         bool       `json:"active"`
	Verified       bool       `json:"verified"`
	Static         bool       `json:"static_finding"`
	Dynamic        bool       `json:"dynamic_finding"`
	UniqueID       string     `json:"unique_id_from_tool"`
	VulnIDFromTool string     `json:"vuln_id_from_tool,omitempty"`
	Component      string     `json:"component_name,omitempty"`
	ComponentVer   string     `json:"component_version,omitempty"`
	Endpoints      []endpoint `json:"endpoints,omitempty"`
	Tags           []string   `json:"tags,omitempty"`
}

type endpoint struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
}

// volatile: nagłówki zmieniające się przy każdym zapytaniu. Pomijamy je w opisie, bo DefectDojo deduplikuje
// findingi po skrócie (m.in. z opisu): inaczej reimport traktowałby każdy skan jako nowe findingi.
var volatile = map[string]bool{"date": true, "expires": true, "age": true, "etag": true, "last-modified": true, "set-cookie": true,
	"x-request-id": true, "x-runtime": true, "cf-ray": true, "content-length": true, "x-amz-request-id": true, "report-to": true, "nel": true}

// BuildFindings: zamiana obserwacji na findingi informacyjne (jeden na usługę, opis zawiera dowody).
func BuildFindings(obs []*scan.Observation) []finding {
	date := time.Now().Format("2006-01-02")
	out := []finding{} // pusta lista jako [] (DefectDojo wywraca się na null)
	for _, o := range obs {
		flags := append([]string(nil), o.Flags...)
		sort.Strings(flags) // także dla starszych wyników zapisanych przed sortowaniem flag
		o.Flags = flags
		var d strings.Builder
		fmt.Fprintf(&d, "**Usługa:** %s/%d %s %s %s\n\n", o.IP, o.Port, o.Proto, o.Service, strings.TrimSpace(o.Product+" "+o.Version))
		fmt.Fprintf(&d, "**Ciekawość (MoNet):** %d/100\n\n", o.Interest)
		if len(o.Flags) > 0 {
			fmt.Fprintf(&d, "**Flagi:** %s\n\n", strings.Join(o.Flags, ", "))
		}
		if len(o.Data.Detections) > 0 {
			d.WriteString("**Wykryte technologie:**\n")
			for _, t := range o.Data.Detections {
				fmt.Fprintf(&d, "- %s %s (%s, pewność %d%%): %s\n", t.Name, t.Version, t.Category, t.Confidence, strings.Join(t.Evidence, "; "))
			}
			d.WriteString("\n")
		}
		proto := "tcp"
		if h := o.Data.HTTP; h != nil && h.Error == "" {
			proto = h.Scheme
			fmt.Fprintf(&d, "**HTTP:** %d, tytuł: %q, URL: %s\n\n", h.Status, h.Title, h.FinalURL)
			keys := make([]string, 0, len(h.Headers))
			for k := range h.Headers {
				if !volatile[k] {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			d.WriteString("**Nagłówki:**\n```\n")
			for _, k := range keys {
				fmt.Fprintf(&d, "%s: %s\n", k, strings.Join(h.Headers[k], ", "))
			}
			d.WriteString("```\n")
			if len(h.Cookies) > 0 {
				var cs []string
				for _, c := range h.Cookies {
					cs = append(cs, fmt.Sprintf("%s (Secure=%v, HttpOnly=%v)", c.Name, c.Secure, c.HttpOnly))
				}
				fmt.Fprintf(&d, "\n**Ciasteczka:** %s\n", strings.Join(cs, ", "))
			}
			if t := h.TLS; t != nil {
				fmt.Fprintf(&d, "\n**TLS:** %s, %s, ważny do %s, self-signed=%v, wygasły=%v\n", t.Version, t.Subject, t.NotAfter.Format("2006-01-02"), t.SelfSigned, t.Expired)
			}
		}
		title := fmt.Sprintf("[MoNet] %s:%d/%s %s", o.IP, o.Port, o.Proto, o.Service)
		comp, ver := o.Product, o.Version
		if len(o.Data.Detections) > 0 {
			best := o.Data.Detections[0]
			for _, d := range o.Data.Detections {
				if d.Interest*d.Confidence > best.Interest*best.Confidence {
					best = d
				}
			}
			title += " – " + best.Name
			if comp == "" {
				comp, ver = best.Name, best.Version
			}
		} else if len(o.Techs) > 0 {
			title += " – " + o.Techs[0].Name
		}
		tags := append([]string{"asi", "discovery"}, o.Flags...)
		out = append(out, finding{Title: title, Description: d.String(), Severity: "Info", Date: date, Active: true, Static: false, Dynamic: true,
			UniqueID: fmt.Sprintf("asi-%s-%d-%s", o.IP, o.Port, o.Proto), VulnIDFromTool: "asi-observation",
			Component: comp, ComponentVer: ver, Endpoints: []endpoint{{Host: o.IP, Port: o.Port, Protocol: proto}}, Tags: tags})
	}
	return out
}

func GenericJSON(obs []*scan.Observation) []byte {
	b, _ := json.MarshalIndent(map[string]any{"findings": BuildFindings(obs)}, "", "  ")
	return b
}

// Push: import-scan do DefectDojo (auto_create_context tworzy produkt i engagement, jeśli nie istnieją).
func Push(ctx context.Context, s Settings, obs []*scan.Observation, scanName string) (map[string]any, error) {
	return push(ctx, s, obs, scanName, "import-scan")
}

// Reimport: aktualizacja stałego testu (np. „MoNet – <konfiguracja>”): DefectDojo dopisuje nowe findingi,
// a te, których nie ma w nowym wyniku, zamyka (close_old_findings). Zmiany w czasie widać też w DefectDojo.
func Reimport(ctx context.Context, s Settings, obs []*scan.Observation, testTitle string) (map[string]any, error) {
	return push(ctx, s, obs, testTitle, "reimport-scan")
}

func push(ctx context.Context, s Settings, obs []*scan.Observation, scanName, endpoint string) (map[string]any, error) {
	if s.URL == "" || s.Token == "" {
		return nil, errors.New("skonfiguruj adres i token DefectDojo w ustawieniach")
	}
	if len(obs) == 0 && endpoint == "import-scan" {
		return nil, errors.New("brak obserwacji do wysłania")
	}
	if s.Product == "" {
		s.Product = "MoNet discovery"
	}
	if s.Engagement == "" {
		s.Engagement = "MoNet " + time.Now().Format("2006-01")
	}
	cl := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !s.VerifyTLS}}}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fields := map[string]string{
		"scan_type": "Generic Findings Import", "product_name": s.Product, "engagement_name": s.Engagement,
		"product_type_name": productTypeFor(ctx, cl, s), "auto_create_context": "true", "minimum_severity": "Info", "active": "true",
		"verified": "false", "scan_date": time.Now().UTC().Format("2006-01-02"), "test_title": scanName, "close_old_findings": "false",
		"deduplication_on_engagement": "true",
	}
	if endpoint == "reimport-scan" {
		fields["close_old_findings"] = "true"
		fields["do_not_reactivate"] = "false"
	}
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("file", "asi-findings.json")
	_, _ = fw.Write(GenericJSON(obs))
	_ = mw.Close()
	url := strings.TrimRight(s.URL, "/") + "/api/v2/" + endpoint + "/"
	payload := body.Bytes()
	var rb []byte
	// ponowienie przy błędzie sieci, 429 i 5xx (DefectDojo bywa chwilowo zajęty przy dużym imporcie); 4xx bez ponowień
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Token "+s.Token)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := cl.Do(req)
		retry := err != nil
		if err == nil {
			rb, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			retry = resp.StatusCode == 429 || resp.StatusCode >= 500
			if !retry && resp.StatusCode >= 300 {
				return nil, fmt.Errorf("DefectDojo %d: %s", resp.StatusCode, strings.TrimSpace(string(rb[:min(len(rb), 500)])))
			}
			if retry && attempt >= 2 {
				return nil, fmt.Errorf("DefectDojo %d po %d próbach: %s", resp.StatusCode, attempt+1, strings.TrimSpace(string(rb[:min(len(rb), 300)])))
			}
		} else if attempt >= 2 {
			return nil, fmt.Errorf("DefectDojo niedostępny po %d próbach: %w", attempt+1, err)
		}
		if !retry {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(2+3*attempt) * time.Second):
		}
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	return out, nil
}

// productTypeFor: typ produktu do wysyłki. Jeśli produkt już istnieje w DefectDojo, używamy jego typu
// (inaczej DefectDojo odrzuca import: „product has a conflict with the supplied product type”, np. po zmianie nazwy narzędzia).
func productTypeFor(ctx context.Context, cl *http.Client, s Settings) string {
	const def = "MoNet"
	get := func(path string, out any) bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.URL, "/")+"/api/v2/"+path, nil)
		if err != nil {
			return false
		}
		req.Header.Set("Authorization", "Token "+s.Token)
		resp, err := cl.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == 200 && json.NewDecoder(resp.Body).Decode(out) == nil
	}
	var prods struct {
		Results []struct {
			Name     string `json:"name"`
			ProdType int    `json:"prod_type"`
		} `json:"results"`
	}
	if !get("products/?name="+url.QueryEscape(s.Product), &prods) {
		return def
	}
	for _, p := range prods.Results {
		if p.Name == s.Product && p.ProdType > 0 {
			var pt struct {
				Name string `json:"name"`
			}
			if get(fmt.Sprintf("product_types/%d/", p.ProdType), &pt) && pt.Name != "" {
				return pt.Name
			}
		}
	}
	return def
}

// Test: sprawdzenie połączenia (GET /api/v2/user_contact_infos/ wymaga ważnego tokenu).
func Test(ctx context.Context, s Settings) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.URL, "/")+"/api/v2/products/?limit=1", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+s.Token)
	cl := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !s.VerifyTLS}}}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("DefectDojo odpowiedział %d", resp.StatusCode)
	}
	return nil
}

// PushStats: podsumowanie odpowiedzi DefectDojo (statistics.delta przy reimporcie, statistics.after przy imporcie).
type PushStats struct {
	TestID      int
	Created     int
	Closed      int
	Reactivated int
	Untouched   int
	TotalAfter  int
}

func sumSeverities(v any) int {
	m, ok := v.(map[string]any)
	if !ok {
		return 0
	}
	// DefectDojo zwraca poziomy ważności ORAZ klucz "total" (suma): bierzemy tylko sumę, inaczej wynik byłby podwojony
	if tot, ok := m["total"].(map[string]any); ok {
		if t, ok := tot["total"].(float64); ok {
			return int(t)
		}
	}
	n := 0
	for k, sev := range m {
		if k == "total" {
			continue
		}
		if sm, ok := sev.(map[string]any); ok {
			if t, ok := sm["total"].(float64); ok {
				n += int(t)
			}
		}
	}
	return n
}

func Stats(resp map[string]any) PushStats {
	var p PushStats
	if t, ok := resp["test"].(float64); ok {
		p.TestID = int(t)
	} else if t, ok := resp["test_id"].(float64); ok {
		p.TestID = int(t)
	}
	st, _ := resp["statistics"].(map[string]any)
	if d, ok := st["delta"].(map[string]any); ok {
		p.Created, p.Closed, p.Reactivated, p.Untouched = sumSeverities(d["created"]), sumSeverities(d["closed"]), sumSeverities(d["reactivated"]), sumSeverities(d["untouched"])
	}
	if a, ok := st["after"].(map[string]any); ok {
		if tot, ok := a["total"].(map[string]any); ok {
			if t, ok := tot["active"].(float64); ok {
				p.TotalAfter = int(t)
			}
		}
		if p.Created == 0 && p.Closed == 0 && p.Untouched == 0 {
			if tot, ok := a["total"].(map[string]any); ok {
				if t, ok := tot["total"].(float64); ok && st["delta"] == nil {
					p.Created = int(t)
				}
			}
		}
	}
	return p
}

// Record: zapis wysyłki w historii (zapiski z testów integracji).
func Record(db interface {
	Exec(string, ...any) (sql.Result, error)
}, user string, scanID int64, mode, title string, sent int, resp map[string]any, perr error) {
	p := Stats(resp)
	e := ""
	if perr != nil {
		e = perr.Error()
	}
	_, _ = db.Exec(`INSERT INTO dojo_pushes(ts,username,scan_id,mode,test_title,test_id,sent,created,closed,reactivated,untouched,total_after,error)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, time.Now().UTC().Format(time.RFC3339), user, scanID, mode, title, p.TestID, sent, p.Created, p.Closed, p.Reactivated, p.Untouched, p.TotalAfter, e)
}
