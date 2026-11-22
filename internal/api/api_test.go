package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asi-agh/asi/internal/auth"
	"github.com/asi-agh/asi/internal/scan"
	"github.com/asi-agh/asi/internal/secure"
	"github.com/asi-agh/asi/internal/sig"
	"github.com/asi-agh/asi/internal/store"
)

// Test integracyjny API na pustej bazie: logowanie, RBAC, walidacja, polityka, odpowiedzi bez null.
func TestAPIIntegration(t *testing.T) {
	box, _ := secure.NewBox(make([]byte, 32))
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	as := auth.New(st, []byte("api-test-secret-0123456789abcdef"))
	if _, err := as.Seed("admin", "admin-haslo-12", true); err != nil {
		t.Fatal(err)
	}
	if _, err := as.CreateUser("obs", "obserwator-12", "Obserwator"); err != nil {
		t.Fatal(err)
	}
	sigs := sig.NewEngine(nil)
	if err := SyncSignatures(st, sigs); err != nil {
		t.Fatal(err)
	}
	lg := log.New(io.Discard, "", 0)
	srv := httptest.NewServer((&Server{S: st, A: as, E: scan.NewEngine(st, sigs, lg), Sigs: sigs, Log: lg}).Router())
	defer srv.Close()

	client := func() *http.Client { j, _ := cookiejar.New(nil); return &http.Client{Jar: j} }
	call := func(c *http.Client, method, path string, body any) (int, string) {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, srv.URL+"/api"+path, rd)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	admin, obs := client(), client()
	if c, _ := call(admin, "GET", "/me", nil); c != 401 {
		t.Fatalf("bez logowania: %d", c)
	}
	if c, b := call(admin, "POST", "/auth/login", map[string]string{"username": "admin", "password": "admin-haslo-12"}); c != 200 || strings.Contains(b, `"token"`) {
		t.Fatalf("logowanie admina: %d %s", c, b)
	}
	if c, _ := call(obs, "POST", "/auth/login", map[string]string{"username": "obs", "password": "obserwator-12"}); c != 200 {
		t.Fatal("logowanie obserwatora")
	}
	// RBAC po stronie serwera
	if c, _ := call(obs, "POST", "/targets", map[string]string{"text": "10.1.2.3"}); c != 403 {
		t.Fatalf("obserwator dodał cel: %d", c)
	}
	if c, _ := call(obs, "PUT", "/settings/policy", map[string]any{"allow_cidrs": []string{"10.0.0.0/8"}}); c != 403 {
		t.Fatalf("obserwator zmienił politykę: %d", c)
	}
	// walidacja celów i polityka domyślna (tylko sieci prywatne)
	_, b := call(admin, "POST", "/targets", map[string]string{"text": "10.1.2.0/24\n10.1.2.300\n8.8.8.8"})
	var res struct {
		Added  int      `json:"added"`
		Errors []string `json:"errors"`
	}
	_ = json.Unmarshal([]byte(b), &res)
	if res.Added != 1 || len(res.Errors) != 2 {
		t.Fatalf("cele: %s", b)
	}
	// pusta lista portów odrzucona
	if c, _ := call(admin, "POST", "/configs", map[string]any{"name": "t", "ports": ""}); c != 400 {
		t.Fatalf("pusta lista portów: %d", c)
	}
	// nieistniejące zasoby: 404
	for _, p := range []string{"/scans/99999", "/observations/99999"} {
		if c, _ := call(admin, "GET", p, nil); c != 404 {
			t.Errorf("%s: %d", p, c)
		}
	}
	// listy zwracają [] zamiast null (null w UI = czarny ekran)
	for _, p := range []string{"/scans", "/configs", "/targets", "/services", "/hosts", "/technologies", "/dojo/history", "/audit/days"} {
		c, b := call(admin, "GET", p, nil)
		if c != 200 || strings.TrimSpace(b) == "null" || strings.Contains(b, ":null") && p != "/technologies" {
			t.Errorf("%s: %d %.120s", p, c, b)
		}
	}
	// wylogowanie unieważnia sesję
	call(admin, "POST", "/auth/logout", map[string]string{})
	if c, _ := call(admin, "GET", "/me", nil); c != 401 {
		t.Fatalf("po wylogowaniu: %d", c)
	}
}
