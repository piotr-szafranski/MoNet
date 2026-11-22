package scan

import (
	"sort"
	"strings"

	"github.com/asi-agh/asi/internal/httpprobe"
	"github.com/asi-agh/asi/internal/sig"
)

var standardHTTP = map[int]bool{80: true, 443: true, 8080: true, 8443: true}

// Score: klasa (priorytet analityczny 0–100) liczona z reguł klasy (tabela scoring_rules, edytowalna w UI)
// oraz flagi do dashboardu. o.Rules: lista dopasowanych reguł (do „pokrycia” X z N).
func Score(o *Observation) {
	flags := map[string]bool{}
	matched := map[string]bool{}
	score := 0
	top := 0
	heur := func(key string, def int) {
		w, ok, on := rules.weight("heuristic", key)
		if !ok {
			w, on = def, true
		}
		if on {
			score += w
			matched["heuristic:"+key] = true
		}
	}
	for _, d := range o.Data.Detections {
		iw, ok, on := rules.weight("signature", d.ID)
		if !ok {
			iw, on = d.Interest, true
		}
		if on {
			w := iw * d.Confidence / 100
			score += w / 2
			if w > top {
				top = w
			}
			matched["signature:"+d.ID] = true
		}
		switch d.Category {
		case "admin-panel":
			flags["panel-admin"] = true
		case "staging":
			flags["staging"] = true
		case "iot":
			flags["iot"] = true
		case "devops":
			flags["devops"] = true
		case "database":
			flags["baza-danych"] = true
		case "cms":
			flags["cms"] = true
		case "interesting":
			flags["artefakt"] = true
		}
	}
	score += top / 2
	if h := o.Data.HTTP; h != nil && h.Error == "" {
		if exposed, _ := PlainHTTPBesideTLS(h.Scheme, h.FinalURL, h.Redirects, h.AltScheme, h.AltFinalURL); exposed {
			flags["http-obok-https"] = true
			heur("http-obok-https", 6)
		}
		if h.ResponseMs >= 500 {
			flags["wolna-odpowiedz"] = true
			heur("wolna-odpowiedz", 2)
		}
		if h.TLSError != "" {
			flags["tls-bez-certyfikatu"] = true
			heur("tls-bez-certyfikatu", 4)
		}
		if t := h.TLS; t != nil {
			if t.Expired {
				flags["cert-wygasly"] = true
				heur("cert-wygasly", 10)
			} else if t.DaysLeft < 30 {
				flags["cert-wygasa"] = true
				heur("cert-wygasa", 4)
			}
			if t.SelfSigned {
				flags["cert-self-signed"] = true
				heur("cert-self-signed", 4)
			}
			if t.Version == "TLS 1.0" || t.Version == "TLS 1.1" {
				flags["stary-tls"] = true
				heur("stary-tls", 6)
			}
		} else if hasDetection(o.Data.Detections, "login-form") {
			flags["logowanie-bez-tls"] = true
			heur("logowanie-bez-tls", 12)
		}
		if v := first(h.Headers, "server"); strings.ContainsAny(v, "0123456789") {
			flags["ujawniona-wersja"] = true
			heur("wersja-server", 3)
		}
		if first(h.Headers, "x-powered-by") != "" {
			flags["ujawniona-wersja"] = true
			heur("wersja-x-powered-by", 3)
		}
		for _, c := range h.Cookies {
			if !c.HttpOnly && looksLikeSession(c.Name) {
				flags["ciasteczko-bez-httponly"] = true
				heur("ciasteczko-bez-httponly", 3)
				break
			}
		}
		if !standardHTTP[o.Port] {
			flags["niestandardowy-port-http"] = true
			heur("niestandardowy-port-http", 4)
		}
	}
	if o.Product != "" && o.Version != "" {
		heur("znana-wersja", 1)
	}
	if w, ok, on := rules.weight("port", portKey(o.Proto, o.Port)); ok && on {
		score += w
		if w > 0 {
			matched["port:"+portKey(o.Proto, o.Port)] = true
		}
	}
	o.Interest = max(0, min(score, 100))
	o.Flags = o.Flags[:0]
	for f := range flags {
		o.Flags = append(o.Flags, f)
	}
	sort.Strings(o.Flags) // stała kolejność: stabilny odcisk i deduplikacja w DefectDojo
	o.Rules = o.Rules[:0]
	for k := range matched {
		o.Rules = append(o.Rules, k)
	}
	sort.Strings(o.Rules)
}

func looksLikeSession(n string) bool {
	n = strings.ToLower(n)
	return strings.Contains(n, "sess") || strings.Contains(n, "sid") || strings.Contains(n, "auth") || strings.Contains(n, "token")
}

func hasDetection(ds []sig.Detection, id string) bool {
	for _, d := range ds {
		if d.ID == id {
			return true
		}
	}
	return false
}

func first(h map[string][]string, k string) string {
	if v := h[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// PlainHTTPBesideTLS: port odpowiada i po HTTPS, i po HTTP, a wariant HTTP serwuje treść zamiast przekierować na HTTPS
// (ruch, hasła i ciasteczka mogą iść otwartym tekstem). Zwraca też, czy port w ogóle obsługuje oba schematy.
func PlainHTTPBesideTLS(scheme, final string, redirects []string, alt, altFinal string) (exposed, dual bool) {
	if alt == "" {
		return false, false
	}
	httpFinal := altFinal
	if scheme == "http" {
		httpFinal = final
	}
	return !strings.HasPrefix(httpFinal, "https://"), true
}

// SigInput: zamiana obserwacji na wejście silnika sygnatur.
func SigInput(o *Observation) sig.Input {
	in := sig.Input{Port: o.Port, Service: o.Service, Hostname: o.Data.Hostname,
		Banner: strings.TrimSpace(strings.Join([]string{o.Data.Banner.Product, o.Data.Banner.Version, o.Data.Banner.ExtraInfo}, " "))}
	if h := o.Data.HTTP; h != nil && h.Error == "" {
		in.Status, in.Title, in.Headers, in.Body = h.Status, h.Title, h.Headers, h.Body
		for _, c := range h.Cookies {
			in.Cookies = append(in.Cookies, c.Name)
		}
		in.FavHash = h.FaviconHash
		if t := h.TLS; t != nil {
			in.CertText = t.Subject + " | " + t.Issuer + " | " + strings.Join(t.SANs, " ")
		}
		in.PathHits = map[string]sig.PathResponse{}
		for p, r := range h.Paths {
			in.PathHits[p] = sig.PathResponse{Status: r.Status, Body: r.Body, Title: r.Title}
		}
	}
	return in
}

var _ = httpprobe.UserAgent
