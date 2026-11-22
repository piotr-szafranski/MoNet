package auth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/asi-agh/asi/internal/secure"
	"github.com/asi-agh/asi/internal/store"
)

func newSvc(t *testing.T) *Service {
	t.Helper()
	box, err := secure.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	a := New(st, []byte("test-secret-0123456789abcdef0123"))
	if _, err := a.Seed("admin", "admin-haslo-1!", true); err != nil {
		t.Fatal(err)
	}
	return a
}

// RBAC po stronie serwera + unieważnienie tokenu: wylogowanie i zmiana hasła.
func TestRBACAndRevocation(t *testing.T) {
	a := newSvc(t)
	if _, _, err := a.Login("admin", "zle"); err == nil {
		t.Fatal("złe hasło przyjęte")
	}
	tokAdmin, _, err := a.Login("admin", "admin-haslo-1!")
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.CreateUser("obs-test", "obserwator-1!", "Obserwator")
	if err != nil {
		t.Fatal(err)
	}
	tokObs, _, err := a.Login("obs-test", "obserwator-1!")
	if err != nil {
		t.Fatal(err)
	}
	h := a.Middleware(Require(SettingsManage, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	call := func(tok string) int {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/x", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if c := call(tokAdmin); c != 200 {
		t.Fatalf("admin: %d", c)
	}
	if c := call(tokObs); c != 403 {
		t.Fatalf("obserwator bez uprawnienia: %d", c)
	}
	if c := call("smieci"); c != 401 {
		t.Fatalf("zły token: %d", c)
	}
	a.Revoke(tokAdmin)
	if c := call(tokAdmin); c != 401 {
		t.Fatalf("token po wylogowaniu: %d", c)
	}
	// zmiana hasła: wcześniejsze sesje nieważne
	if _, err := a.S.DB.Exec(`UPDATE users SET token_gen=token_gen+1 WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	ok := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tokObs)
	ok.ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Fatalf("token sprzed zmiany hasła: %d", rr.Code)
	}
}
