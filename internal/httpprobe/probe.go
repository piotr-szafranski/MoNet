// Package httpprobe: bezpieczne pobieranie informacji o usługach HTTP/HTTPS (tylko GET, bez logowania,
// limit tempa, przekierowania tylko w obrębie zakresu skanu).
package httpprobe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxBody      = 512 << 10
	snippetLen   = 4096
	maxRedirects = 5
	UserAgent    = "MoNet-DiscoveryScanner/1.0 (+bezpieczny skan discovery; CBI AGH prototyp)"
)

type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"` // przechowywane zaszyfrowane razem z całym blobem
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"httponly"`
	SameSite string `json:"samesite,omitempty"`
}

type TLSInfo struct {
	Version    string    `json:"version"`
	Cipher     string    `json:"cipher"`
	SubjectCN  string    `json:"subject_cn"`
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	SANs       []string  `json:"sans,omitempty"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed"`
	Expired    bool      `json:"expired"`
	DaysLeft   int       `json:"days_left"`
	SHA256     string    `json:"sha256"`
}

type PathHit struct {
	Status int    `json:"status"`
	Title  string `json:"title,omitempty"`
	Length int    `json:"length"`
	Body   string `json:"-"`
}

type Result struct {
	URL          string              `json:"url"`
	FinalURL     string              `json:"final_url"`
	Scheme       string              `json:"scheme"`
	Status       int                 `json:"status"`
	Title        string              `json:"title"`
	Headers      map[string][]string `json:"headers"`
	Cookies      []Cookie            `json:"cookies,omitempty"`
	Redirects    []string            `json:"redirects,omitempty"`
	TLS          *TLSInfo            `json:"tls,omitempty"`
	BodyLength   int                 `json:"body_length"`
	BodySHA256   string              `json:"body_sha256"`
	BodySnippet  string              `json:"body_snippet,omitempty"`
	FaviconHash  *int32              `json:"favicon_hash,omitempty"`
	Paths        map[string]PathHit  `json:"paths,omitempty"`
	SoftNotFound bool                `json:"soft_404,omitempty"` // serwer odpowiada 200 na nieistniejące ścieżki
	Error        string              `json:"error,omitempty"`
	TLSError     string              `json:"tls_error,omitempty"`
	ResponseMs   int64               `json:"response_ms,omitempty"`   // czas pierwszej odpowiedzi strony głównej
	AltScheme    string              `json:"alt_scheme,omitempty"`    // port odpowiada też drugim schematem (np. Traefik: HTTP i HTTPS na jednym porcie)
	AltStatus    int                 `json:"alt_status,omitempty"`    // kod odpowiedzi drugiego schematu
	AltFinalURL  string              `json:"alt_final_url,omitempty"` // port wymaga TLS, ale uzgodnienie się nie udało (np. brak certyfikatu bez SNI)
	DurationMs   int64               `json:"duration_ms"`
	Body         string              `json:"-"`
}

// Limiter: prosty token bucket wspólny dla wszystkich zapytań HTTP skanu.
type Limiter struct {
	mu   sync.Mutex
	next time.Time
	gap  time.Duration
}

func NewLimiter(rps int) *Limiter {
	if rps <= 0 {
		rps = 10
	}
	return &Limiter{gap: time.Second / time.Duration(rps)}
}

func (l *Limiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(l.gap)
	l.mu.Unlock()
	if d := time.Until(at); d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

type Prober struct {
	Limiter *Limiter
	Timeout time.Duration
	InScope func(host string) bool // czy wolno podążyć za przekierowaniem na ten host
	Paths   []string               // ścieżki z sygnatur (tylko GET)
	client  *http.Client
}

func New(l *Limiter, timeout time.Duration, inScope func(string) bool, paths []string) *Prober {
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}, // chcemy odczytać każdy certyfikat
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
		MaxIdleConns:          0,
		Proxy:                 nil,
	}
	return &Prober{Limiter: l, Timeout: timeout, InScope: inScope, Paths: paths, client: &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Probe: pobiera stronę główną na ip:port (z nagłówkiem Host, jeśli znamy domenę), favicon i ścieżki z sygnatur.
func (p *Prober) Probe(ctx context.Context, ip string, port int, hostname string, preferTLS bool) *Result {
	start := time.Now()
	schemes := []string{"http", "https"}
	if preferTLS {
		schemes = []string{"https", "http"}
	}
	var res, plain *Result
	httpsErr := ""
	tried := map[string]bool{}
	for _, sch := range schemes {
		tried[sch] = true
		r := p.fetchMain(ctx, sch, ip, port, hostname)
		res = r
		if r.Error == "" && !looksLikeWrongScheme(r) {
			break
		}
		if sch == "https" && r.Error != "" {
			httpsErr = r.Error
		}
		if r.Error == "" && plain == nil {
			plain = r
		}
	}
	if res.Error != "" && plain != nil {
		res = plain // nie udało się po TLS, ale port odpowiedział po HTTP: zostaw odpowiedź HTTP
	}
	if res.Error == "" && looksLikeWrongScheme(res) {
		// port mówi „wyślij TLS”, a uzgodnienie TLS (bez nazwy hosta) się nie udało
		res.TLSError = "port wymaga TLS, ale serwer nie przedstawił certyfikatu bez nazwy hosta (SNI)"
		if httpsErr != "" {
			res.TLSError += ": " + httpsErr
		}
	}
	if res.Error == "" && res.TLSError == "" {
		// port dwuprotokołowy: sprawdź drugi schemat (jedno zapytanie); ścieżki sygnatur będą próbowane w obu
		other := map[string]string{"http": "https", "https": "http"}[res.Scheme]
		if !tried[other] {
			if r := p.fetchMain(ctx, other, ip, port, hostname); r.Error == "" && !looksLikeWrongScheme(r) && r.Status > 0 {
				res.AltScheme, res.AltStatus, res.AltFinalURL = other, r.Status, r.FinalURL
			}
		}
	}
	if res.Error == "" {
		base := res.Scheme + "://" + net.JoinHostPort(ip, strconv.Itoa(port))
		p.favicon(ctx, res, base, hostname)
	}
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

// FetchPaths: GET na wskazane ścieżki (bez logowania, z limitem tempa).
func (p *Prober) FetchPaths(ctx context.Context, res *Result, ip string, port int, hostname string, paths []string) {
	if res == nil || res.Error != "" {
		return
	}
	base := res.Scheme + "://" + net.JoinHostPort(ip, strconv.Itoa(port))
	if res.Paths == nil {
		res.Paths = map[string]PathHit{}
	}
	t0 := time.Now()
	// soft-404: część serwerów (urządzenia wbudowane, SPA) odpowiada 200 na każdą ścieżkę. Zapytanie kontrolne
	// o nieistniejącą ścieżkę pozwala odrzucić trafienia, które wyglądają tak samo jak odpowiedź „nie ma takiej strony”.
	var ctrl string
	ctrlOK := false
	if len(paths) > 0 {
		if r, body, err := p.get(ctx, base+"/monet-kontrola-404-"+strconv.FormatInt(time.Now().UnixNano()%1e9, 36), hostname); err == nil && r.StatusCode == 200 {
			ctrl, ctrlOK = body, true
			res.SoftNotFound = true
		}
	}
	for _, path := range paths {
		if ctx.Err() != nil {
			break
		}
		r, body, err := p.get(ctx, base+path, hostname)
		if (err != nil || r.StatusCode == 404) && res.AltScheme != "" {
			// na porcie dwuprotokołowym ścieżka bywa dostępna tylko jednym schematem (np. dashboard Traefika tylko po HTTP)
			alt := res.AltScheme + "://" + net.JoinHostPort(ip, strconv.Itoa(port))
			if r2, b2, err2 := p.get(ctx, alt+path, hostname); err2 == nil && r2.StatusCode != 404 {
				r, body, err = r2, b2, nil
			}
		}
		if err != nil {
			continue
		}
		if ctrlOK && r.StatusCode == 200 && SameAsControl(body, ctrl) {
			continue // ta sama odpowiedź co dla nieistniejącej ścieżki: to nie jest trafienie
		}
		res.Paths[path] = PathHit{Status: r.StatusCode, Title: extractTitle(body), Length: len(body), Body: truncate(body, 8192)}
	}
	res.DurationMs += time.Since(t0).Milliseconds()
}

func looksLikeWrongScheme(r *Result) bool {
	if r.Status == 400 && (strings.Contains(strings.ToLower(r.Body), "plain http request was sent to https") ||
		strings.Contains(strings.ToLower(r.Body), "speaking plain http to an ssl")) {
		return true
	}
	return false
}

func (p *Prober) get(ctx context.Context, u, hostname string) (*http.Response, string, error) {
	return p.getNoWait(ctx, u, hostname, false)
}

// getNoWait: GET; skipWait = limiter już odczekany przez wołającego.
func (p *Prober) getNoWait(ctx context.Context, u, hostname string, skipWait bool) (*http.Response, string, error) {
	if !skipWait {
		if err := p.Limiter.Wait(ctx); err != nil {
			return nil, "", err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
	if hostname != "" {
		req.Host = hostname
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp, string(b), nil
}

func (p *Prober) fetchMain(ctx context.Context, scheme, ip string, port int, hostname string) *Result {
	u := scheme + "://" + net.JoinHostPort(ip, strconv.Itoa(port)) + "/"
	res := &Result{URL: u, Scheme: scheme}
	cur, host := u, hostname
	for hop := 0; hop <= maxRedirects; hop++ {
		if hop == 0 {
			if err := p.Limiter.Wait(ctx); err != nil { // czekanie w kolejce limitera nie wlicza się do czasu odpowiedzi
				res.Error = simplifyErr(err)
				return res
			}
		}
		t0 := time.Now()
		resp, body, err := p.getNoWait(ctx, cur, host, hop == 0)
		if err != nil {
			res.Error = simplifyErr(err)
			return res
		}
		if hop == 0 {
			res.ResponseMs = time.Since(t0).Milliseconds()
			if resp.TLS != nil {
				res.TLS = tlsInfo(resp.TLS)
			}
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") != "" {
			loc, err := resp.Request.URL.Parse(resp.Header.Get("Location"))
			if err != nil {
				break
			}
			res.Redirects = append(res.Redirects, fmt.Sprintf("%d → %s", resp.StatusCode, loc.String()))
			if hop == 0 {
				fill(res, resp, body) // zapisujemy też pierwszą odpowiedź (nagłówki/ciasteczka)
			}
			// strażnik zakresu: przekierowanie poza zakres jest tylko zapisywane, nie odwiedzane
			lh := loc.Hostname()
			switch {
			case lh == ip || (hostname != "" && strings.EqualFold(lh, hostname)):
				host = hostname
				loc.Host = net.JoinHostPort(ip, portOf(loc))
			case p.InScope != nil && p.InScope(lh):
				host = ""
			default:
				res.Redirects[len(res.Redirects)-1] += " (poza zakresem, nie odwiedzono)"
				res.FinalURL = cur
				return res
			}
			cur = loc.String()
			continue
		}
		fill(res, resp, body)
		res.FinalURL = cur
		return res
	}
	res.FinalURL = cur
	return res
}

func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func fill(res *Result, resp *http.Response, body string) {
	res.Status = resp.StatusCode
	res.Headers = map[string][]string{}
	for k, v := range resp.Header {
		res.Headers[strings.ToLower(k)] = v
	}
	res.Cookies = nil
	for _, c := range resp.Cookies() {
		ss := ""
		switch c.SameSite {
		case http.SameSiteLaxMode:
			ss = "Lax"
		case http.SameSiteStrictMode:
			ss = "Strict"
		case http.SameSiteNoneMode:
			ss = "None"
		}
		res.Cookies = append(res.Cookies, Cookie{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path, Secure: c.Secure, HttpOnly: c.HttpOnly, SameSite: ss})
	}
	res.Body = body
	res.BodyLength = len(body)
	sum := sha256.Sum256([]byte(body))
	res.BodySHA256 = hex.EncodeToString(sum[:])
	res.BodySnippet = truncate(body, snippetLen)
	res.Title = extractTitle(body)
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return truncate(strings.Join(strings.Fields(html.UnescapeString(m[1])), " "), 300)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func tlsInfo(cs *tls.ConnectionState) *TLSInfo {
	t := &TLSInfo{Version: tls.VersionName(cs.Version), Cipher: tls.CipherSuiteName(cs.CipherSuite)}
	if len(cs.PeerCertificates) == 0 {
		return t
	}
	c := cs.PeerCertificates[0]
	t.SubjectCN = c.Subject.CommonName
	t.Subject = c.Subject.String()
	t.Issuer = c.Issuer.String()
	t.SANs = append(t.SANs, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		t.SANs = append(t.SANs, ip.String())
	}
	t.NotBefore, t.NotAfter = c.NotBefore, c.NotAfter
	t.Expired = time.Now().After(c.NotAfter)
	t.DaysLeft = int(time.Until(c.NotAfter).Hours() / 24)
	t.SelfSigned = c.Subject.String() == c.Issuer.String() && c.CheckSignatureFrom(c) == nil
	sum := sha256.Sum256(c.Raw)
	t.SHA256 = hex.EncodeToString(sum[:])
	_ = x509.ErrUnsupportedAlgorithm
	return t
}

func simplifyErr(err error) string {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case strings.Contains(err.Error(), "connection refused"):
		return "connection refused"
	case strings.Contains(err.Error(), "malformed HTTP response"), strings.Contains(err.Error(), "server gave HTTP response"):
		return "not http: " + truncate(err.Error(), 120)
	}
	return truncate(err.Error(), 200)
}

func (p *Prober) favicon(ctx context.Context, res *Result, base, hostname string) {
	resp, body, err := p.get(ctx, base+"/favicon.ico", hostname)
	if err != nil || resp.StatusCode != 200 || len(body) == 0 || len(body) > 200<<10 {
		return
	}
	h := FaviconHash([]byte(body))
	res.FaviconHash = &h
}

// FaviconHash: mmh3 z base64 (z łamaniem linii co 76 znaków), zgodny z formatem Shodan.
func FaviconHash(data []byte) int32 {
	enc := base64.StdEncoding.EncodeToString(data)
	var b bytes.Buffer
	for i := 0; i < len(enc); i += 76 {
		end := min(i+76, len(enc))
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	return int32(murmur3(b.Bytes(), 0))
}

func murmur3(data []byte, seed uint32) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := seed
	n := len(data) / 4
	for i := 0; i < n; i++ {
		k := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k *= c1
		k = k<<15 | k>>17
		k *= c2
		h ^= k
		h = h<<13 | h>>19
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[n*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = k<<15 | k>>17
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// SameAsControl: czy odpowiedź na ścieżkę jest praktycznie taka sama jak na ścieżkę nieistniejącą
// (ten sam tytuł i długość różniąca się najwyżej o echo ścieżki).
func SameAsControl(body, ctrl string) bool {
	if body == ctrl {
		return true
	}
	if extractTitle(body) != extractTitle(ctrl) {
		return false
	}
	d := len(body) - len(ctrl)
	if d < 0 {
		d = -d
	}
	return d <= 64+len(ctrl)/20
}
