// Package auth: RBAC (role + uprawnienia w bazie), logowanie, JWT i middleware sprawdzające uprawnienia w API.
package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"

	"github.com/asi-agh/asi/internal/secure"
	"github.com/asi-agh/asi/internal/store"
)

// Uprawnienia (rdzeń RBAC). Role to nazwane zbiory uprawnień, można tworzyć własne.
const (
	UsersManage    = "users.manage"
	RolesManage    = "roles.manage"
	SettingsManage = "settings.manage"
	AuditRead      = "audit.read"

	TargetsRead   = "targets.read"
	TargetsCreate = "targets.create"
	TargetsUpdate = "targets.update"
	TargetsDelete = "targets.delete"

	ConfigsRead   = "configs.read"
	ConfigsCreate = "configs.create"
	ConfigsUpdate = "configs.update"
	ConfigsDelete = "configs.delete"

	ScansRead   = "scans.read"
	ScansRun    = "scans.run"
	ScansUpdate = "scans.update"
	ScansDelete = "scans.delete"

	ResultsRead   = "results.read"
	ResultsCreate = "results.create" // import wyników
	ResultsUpdate = "results.update" // edycja wyników i adnotacji
	ResultsDelete = "results.delete"

	SigsRead   = "signatures.read"
	SigsCreate = "signatures.create"
	SigsUpdate = "signatures.update"
	SigsDelete = "signatures.delete"

	ExportData = "data.export"
	DojoPush   = "dojo.push"
)

var AllPermissions = []string{
	UsersManage, RolesManage, SettingsManage, AuditRead,
	TargetsRead, TargetsCreate, TargetsUpdate, TargetsDelete,
	ConfigsRead, ConfigsCreate, ConfigsUpdate, ConfigsDelete,
	ScansRead, ScansRun, ScansUpdate, ScansDelete,
	ResultsRead, ResultsCreate, ResultsUpdate, ResultsDelete,
	SigsRead, SigsCreate, SigsUpdate, SigsDelete,
	ExportData, DojoPush,
}

func filter(pred func(p string) bool) []string {
	var out []string
	for _, p := range AllPermissions {
		if pred(p) {
			out = append(out, p)
		}
	}
	return out
}

var adminOnly = map[string]bool{UsersManage: true, RolesManage: true, SettingsManage: true, AuditRead: true}

// Role wbudowane zgodnie z briefem AGH.
var BuiltinRoles = []struct {
	Name, Desc string
	Perms      []string
}{
	{"Administrator", "Administracja: pełny dostęp, użytkownicy, role, ustawienia", AllPermissions},
	{"Operator", "Dodawanie, usuwanie, modyfikacja (bez administracji)", filter(func(p string) bool { return !adminOnly[p] })},
	{"Analityk", "Modyfikacja i odczyt (bez dodawania i usuwania)", filter(func(p string) bool {
		return strings.HasSuffix(p, ".read") && p != AuditRead || strings.HasSuffix(p, ".update") || p == ExportData // bez dojo.push: wysyłka do DefectDojo tylko Operator i Administrator
	})},
	{"Obserwator", "Tylko odczyt", filter(func(p string) bool { return strings.HasSuffix(p, ".read") && p != AuditRead || p == ExportData })},
}

type Service struct {
	S      *store.Store
	secret []byte
	mu     sync.RWMutex
	cache  map[int64]map[string]bool // role_id → uprawnienia
}

func New(s *store.Store, secret []byte) *Service {
	return &Service{S: s, secret: secret, cache: map[int64]map[string]bool{}}
}

// Seed tworzy role wbudowane i konto administratora przy pierwszym uruchomieniu.
func (a *Service) Seed(adminUser, adminPass string, demoUsers bool) (created []string, err error) {
	for _, r := range BuiltinRoles {
		var id int64
		err := a.S.DB.QueryRow(`SELECT id FROM roles WHERE name=?`, r.Name).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			res, err := a.S.DB.Exec(`INSERT INTO roles(name,description,builtin) VALUES(?,?,1)`, r.Name, r.Desc)
			if err != nil {
				return nil, err
			}
			id, _ = res.LastInsertId()
		} else if err != nil {
			return nil, err
		}
		_, _ = a.S.DB.Exec(`DELETE FROM role_permissions WHERE role_id=?`, id)
		for _, p := range r.Perms {
			if _, err := a.S.DB.Exec(`INSERT INTO role_permissions(role_id,perm) VALUES(?,?)`, id, p); err != nil {
				return nil, err
			}
		}
	}
	var n int
	_ = a.S.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	if n == 0 {
		users := [][3]string{{adminUser, adminPass, "Administrator"}}
		if demoUsers {
			users = append(users, [3]string{"operator", "operator123!", "Operator"}, [3]string{"analityk", "analityk123!", "Analityk"}, [3]string{"obserwator", "obserwator123!", "Obserwator"})
		}
		for _, u := range users {
			if _, err := a.CreateUser(u[0], u[1], u[2]); err != nil {
				return created, err
			}
			created = append(created, u[0])
		}
	}
	a.Invalidate()
	return created, nil
}

func (a *Service) CreateUser(username, password, role string) (int64, error) {
	if utf8.RuneCountInString(password) < 8 {
		return 0, errors.New("hasło musi mieć co najmniej 8 znaków")
	}
	var rid int64
	if err := a.S.DB.QueryRow(`SELECT id FROM roles WHERE name=?`, role).Scan(&rid); err != nil {
		return 0, errors.New("nieznana rola")
	}
	res, err := a.S.DB.Exec(`INSERT INTO users(username,pass_hash,role_id,created_at) VALUES(?,?,?,?)`,
		strings.TrimSpace(username), secure.HashPassword(password), rid, store.Now())
	if err != nil {
		return 0, errors.New("użytkownik już istnieje")
	}
	return res.LastInsertId()
}

func (a *Service) Invalidate() {
	a.mu.Lock()
	a.cache = map[int64]map[string]bool{}
	a.mu.Unlock()
}

func (a *Service) RolePerms(roleID int64) map[string]bool {
	a.mu.RLock()
	p, ok := a.cache[roleID]
	a.mu.RUnlock()
	if ok {
		return p
	}
	p = map[string]bool{}
	rows, err := a.S.DB.Query(`SELECT perm FROM role_permissions WHERE role_id=?`, roleID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			p[s] = true
		}
	}
	a.mu.Lock()
	a.cache[roleID] = p
	a.mu.Unlock()
	return p
}

// ---- sesje ----

type User struct {
	ID       int64           `json:"id"`
	Username string          `json:"username"`
	RoleID   int64           `json:"role_id"`
	Role     string          `json:"role"`
	Perms    map[string]bool `json:"-"`
}

func (u *User) PermList() []string {
	var out []string
	for p := range u.Perms {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (u *User) Can(p string) bool { return u != nil && u.Perms[p] }

type claims struct {
	UID int64 `json:"uid"`
	Gen int64 `json:"gen"` // generacja sesji konta (users.token_gen)
	jwt.RegisteredClaims
}

var ErrBadLogin = errors.New("niepoprawny login lub hasło")

func (a *Service) Login(username, password string) (string, *User, error) {
	var id, rid int64
	var hash string
	var disabled int
	var gen int64
	err := a.S.DB.QueryRow(`SELECT id,pass_hash,role_id,disabled,COALESCE(token_gen,0) FROM users WHERE username=?`, username).Scan(&id, &hash, &rid, &disabled, &gen)
	if err != nil {
		secure.CheckPassword("argon2id$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", password) // stały czas
		return "", nil, ErrBadLogin
	}
	if disabled == 1 || !secure.CheckPassword(hash, password) {
		return "", nil, ErrBadLogin
	}
	_, _ = a.S.DB.Exec(`UPDATE users SET last_login=? WHERE id=?`, store.Now(), id)
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims{UID: id, Gen: gen, RegisteredClaims: jwt.RegisteredClaims{
		ID: hex.EncodeToString(jti), ExpiresAt: jwt.NewNumericDate(time.Now().Add(12 * time.Hour)), IssuedAt: jwt.NewNumericDate(time.Now()), Issuer: "asi",
	}})
	s, err := tok.SignedString(a.secret)
	if err != nil {
		return "", nil, err
	}
	u, err := a.load(id)
	return s, u, err
}

func (a *Service) load(id int64) (*User, error) {
	u := &User{ID: id}
	var disabled int
	err := a.S.DB.QueryRow(`SELECT u.username,u.role_id,r.name,u.disabled FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=?`, id).
		Scan(&u.Username, &u.RoleID, &u.Role, &disabled)
	if err != nil || disabled == 1 {
		return nil, errors.New("konto nieaktywne")
	}
	u.Perms = a.RolePerms(u.RoleID)
	return u, nil
}

type ctxKey struct{}

func FromCtx(ctx context.Context) *User {
	u, _ := ctx.Value(ctxKey{}).(*User)
	return u
}

// Middleware: weryfikuje token (nagłówek Authorization: Bearer lub ciasteczko asi_token).
func (a *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if raw == "" {
			if c, err := r.Cookie("asi_token"); err == nil {
				raw = c.Value
			}
		}
		if raw == "" {
			http.Error(w, `{"error":"wymagane logowanie"}`, http.StatusUnauthorized)
			return
		}
		var c claims
		t, err := jwt.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("zły algorytm")
			}
			return a.secret, nil
		})
		if err != nil || !t.Valid || a.revoked(c.ID) {
			http.Error(w, `{"error":"sesja wygasła"}`, http.StatusUnauthorized)
			return
		}
		u, err := a.load(c.UID)
		if err != nil {
			http.Error(w, `{"error":"konto nieaktywne"}`, http.StatusUnauthorized)
			return
		}
		var gen int64
		_ = a.S.DB.QueryRow(`SELECT COALESCE(token_gen,0) FROM users WHERE id=?`, c.UID).Scan(&gen)
		if c.Gen != gen { // hasło zmienione po wydaniu tokenu
			http.Error(w, `{"error":"sesja wygasła po zmianie hasła"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	})
}

// Revoke: unieważnia token przy wylogowaniu (lista do czasu wygaśnięcia tokenu).
func (a *Service) Revoke(raw string) {
	var c claims
	if _, err := jwt.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) { return a.secret, nil }); err != nil || c.ID == "" {
		return
	}
	exp := time.Now().Add(12 * time.Hour)
	if c.ExpiresAt != nil {
		exp = c.ExpiresAt.Time
	}
	_, _ = a.S.DB.Exec(`INSERT OR IGNORE INTO revoked_tokens(jti,expires) VALUES(?,?)`, c.ID, exp.UTC().Format(time.RFC3339))
	_, _ = a.S.DB.Exec(`DELETE FROM revoked_tokens WHERE expires < ?`, time.Now().UTC().Format(time.RFC3339))
}

func (a *Service) revoked(jti string) bool {
	if jti == "" {
		return true // tokeny bez identyfikatora (sprzed tej wersji) nie są akceptowane
	}
	var one int
	return a.S.DB.QueryRow(`SELECT 1 FROM revoked_tokens WHERE jti=?`, jti).Scan(&one) == nil
}

// Require: sprawdzenie uprawnienia po stronie serwera (nie tylko ukrywanie przycisków w UI).
func Require(perm string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !FromCtx(r.Context()).Can(perm) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"brak uprawnienia: ` + perm + `"}`))
			return
		}
		h(w, r)
	}
}
