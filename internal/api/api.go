// Package api: REST API (JSON) z kontrolą uprawnień po stronie serwera + serwowanie interfejsu WWW.
package api

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/asi-agh/asi/internal/auth"
	"github.com/asi-agh/asi/internal/scan"
	"github.com/asi-agh/asi/internal/sig"
	"github.com/asi-agh/asi/internal/store"
)

//go:embed all:webdist
var webFS embed.FS

type Server struct {
	S      *store.Store
	A      *auth.Service
	E      *scan.Engine
	Sigs   *sig.Engine
	Log    *log.Logger
	Secure bool // ciasteczko Secure (za HTTPS)

	loginMu   sync.Mutex
	loginFail map[string][]time.Time
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer, securityHeaders) // bez RealIP: nagłówki X-Forwarded-For od klienta nie są zaufane (limit prób logowania)
	r.Route("/api", func(r chi.Router) {
		r.Post("/auth/login", s.login)
		r.Post("/auth/logout", s.logout)
		r.Get("/health", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
		r.Group(func(r chi.Router) {
			r.Use(s.A.Middleware)
			r.Get("/me", s.me)
			r.Post("/me/password", s.changeOwnPassword)

			r.Get("/users", auth.Require(auth.UsersManage, s.listUsers))
			r.Post("/users", auth.Require(auth.UsersManage, s.createUser))
			r.Put("/users/{id}", auth.Require(auth.UsersManage, s.updateUser))
			r.Delete("/users/{id}", auth.Require(auth.UsersManage, s.deleteUser))
			r.Get("/roles", s.listRoles)
			r.Get("/permissions", s.listPermissions)
			r.Post("/roles", auth.Require(auth.RolesManage, s.saveRole))
			r.Put("/roles/{id}", auth.Require(auth.RolesManage, s.saveRole))
			r.Delete("/roles/{id}", auth.Require(auth.RolesManage, s.deleteRole))

			r.Get("/targets", auth.Require(auth.TargetsRead, s.listTargets))
			r.Post("/targets", auth.Require(auth.TargetsCreate, s.createTargets))
			r.Post("/targets/import", auth.Require(auth.TargetsCreate, s.importTargets))
			r.Put("/targets/{id}", auth.Require(auth.TargetsUpdate, s.updateTarget))
			r.Delete("/targets/{id}", auth.Require(auth.TargetsDelete, s.deleteTarget))
			r.Post("/targets/delete", auth.Require(auth.TargetsDelete, s.bulkDeleteTargets))

			r.Get("/ports/presets", s.portPresets)
			r.Post("/ports/validate", s.validatePorts)

			r.Get("/configs", auth.Require(auth.ConfigsRead, s.listConfigs))
			r.Post("/configs", auth.Require(auth.ConfigsCreate, s.saveConfig))
			r.Put("/configs/{id}", auth.Require(auth.ConfigsUpdate, s.saveConfig))
			r.Delete("/configs/{id}", auth.Require(auth.ConfigsDelete, s.deleteConfig))
			r.Post("/configs/{id}/run", auth.Require(auth.ScansRun, s.runConfig))
			r.Post("/configs/estimate", auth.Require(auth.ConfigsRead, s.estimateDraft))
			r.Get("/configs/{id}/estimate", auth.Require(auth.ConfigsRead, s.estimateConfig))
			r.Get("/configs/{id}/retry", auth.Require(auth.ConfigsRead, s.retryCandidates))
			r.Post("/configs/{id}/retry", auth.Require(auth.ScansRun, s.retryNow))

			r.Get("/scans", auth.Require(auth.ScansRead, s.listScans))
			r.Get("/scans/{id}", auth.Require(auth.ScansRead, s.getScan))
			r.Put("/scans/{id}", auth.Require(auth.ScansUpdate, s.updateScan))
			r.Delete("/scans/{id}", auth.Require(auth.ScansDelete, s.deleteScan))
			r.Post("/scans/{id}/cancel", auth.Require(auth.ScansRun, s.cancelScan))
			r.Post("/scans/{id}/resume", auth.Require(auth.ScansRun, s.resumeScan))
			r.Post("/scans/{id}/reevaluate", auth.Require(auth.ResultsUpdate, s.reevaluate))
			r.Get("/scans/{id}/observations", auth.Require(auth.ResultsRead, s.scanObservations))
			r.Get("/scans/{id}/hosts", auth.Require(auth.ResultsRead, s.scanHosts))

			r.Get("/observations/{id}", auth.Require(auth.ResultsRead, s.getObservation))
			r.Put("/observations/{id}", auth.Require(auth.ResultsUpdate, s.updateObservation))
			r.Delete("/observations/{id}", auth.Require(auth.ResultsDelete, s.deleteObservation))
			r.Delete("/observations/{id}/override", auth.Require(auth.ResultsUpdate, s.clearOverride))

			r.Get("/hosts", auth.Require(auth.ResultsRead, s.listHosts))
			r.Get("/hosts-views", auth.Require(auth.ResultsRead, s.hostViews))
			r.Get("/services-views", auth.Require(auth.ResultsRead, s.serviceViews))
			r.Get("/technologies/review", auth.Require(auth.ResultsRead, s.techReview))
			r.Post("/technologies/{id}/classify", auth.Require(auth.ResultsUpdate, s.classifyTech))
			r.Get("/hosts/{ip}", auth.Require(auth.ResultsRead, s.getHost))
			r.Get("/services", auth.Require(auth.ResultsRead, s.listServices))
			r.Get("/services/groups", auth.Require(auth.ResultsRead, s.serviceGroups))
			r.Get("/services/classgroups", auth.Require(auth.ResultsRead, s.serviceClassGroups))
			r.Get("/technologies", auth.Require(auth.ResultsRead, s.technologies))
			r.Put("/annotations", auth.Require(auth.ResultsUpdate, s.saveAnnotation))
			r.Get("/diff", auth.Require(auth.ResultsRead, s.diff))
			r.Get("/diff/timeline", auth.Require(auth.ResultsRead, s.diffTimeline))
			r.Get("/dashboard", auth.Require(auth.ResultsRead, s.dashboard))

			r.Get("/signatures", auth.Require(auth.SigsRead, s.listSigs))
			r.Post("/signatures", auth.Require(auth.SigsCreate, s.saveSig))
			r.Put("/signatures/{id}", auth.Require(auth.SigsUpdate, s.saveSig))
			r.Delete("/signatures/{id}", auth.Require(auth.SigsDelete, s.deleteSig))
			r.Post("/signatures/test", auth.Require(auth.SigsRead, s.testSig))
			r.Post("/signatures/import", auth.Require(auth.SigsCreate, s.importSigs))
			r.Get("/signatures/export", auth.Require(auth.SigsRead, s.exportSigs))
			r.Get("/rules", auth.Require(auth.SigsRead, s.listRules))
			r.Post("/rules", auth.Require(auth.SigsCreate, s.createRule))
			r.Put("/rules/{id}", auth.Require(auth.SigsUpdate, s.updateRule))
			r.Delete("/rules/{id}", auth.Require(auth.SigsDelete, s.deleteRule))
			r.Post("/rules/rescore", auth.Require(auth.SigsUpdate, s.rescore))
			r.Get("/settings/policy", auth.Require(auth.ConfigsRead, s.getPolicy))
			r.Put("/settings/policy", auth.Require(auth.SettingsManage, s.putPolicy))
			r.Get("/settings/allowed-ports", auth.Require(auth.ConfigsRead, s.getAllowedPorts))
			r.Put("/settings/allowed-ports", auth.Require(auth.SettingsManage, s.putAllowedPorts))

			r.Post("/import/results", auth.Require(auth.ResultsCreate, s.importResults))
			r.Get("/export/scan/{id}", auth.Require(auth.ExportData, s.exportScan))
			r.Get("/export/services", auth.Require(auth.ExportData, s.exportServices))
			r.Get("/export/targets", auth.Require(auth.ExportData, s.exportTargets))
			r.Get("/export/diff", auth.Require(auth.ExportData, s.exportDiff))

			r.Get("/settings/dojo", auth.Require(auth.SettingsManage, s.getDojo))
			r.Put("/settings/dojo", auth.Require(auth.SettingsManage, s.putDojo))
			r.Post("/dojo/test", auth.Require(auth.SettingsManage, s.testDojo))
			r.Post("/dojo/push", auth.Require(auth.DojoPush, s.pushDojo))
			r.Post("/dojo/retry/{id}", auth.Require(auth.DojoPush, s.retryDojo))
			r.Get("/dojo/preview", auth.Require(auth.DojoPush, s.previewDojo))
			r.Get("/dojo/history", auth.Require(auth.ResultsRead, s.dojoHistory))

			r.Get("/audit", auth.Require(auth.AuditRead, s.listAudit))
			r.Get("/audit/days", auth.Require(auth.AuditRead, s.auditDays))
			r.Get("/audit/export", auth.Require(auth.AuditRead, s.exportAudit))
		})
	})
	sub, _ := fs.Sub(webFS, "webdist")
	files := http.FileServer(http.FS(sub))
	r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
		p := strings.TrimPrefix(req.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err != nil {
			req.URL.Path = "/" // SPA: nieznane ścieżki → index.html
		} else if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, req)
	})
	return r
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// ---- pomocnicze ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 16<<20))
	return dec.Decode(v)
}

func idParam(r *http.Request) int64 {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	return id
}

func qint(r *http.Request, k string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(k)); err == nil {
		return v
	}
	return def
}

func user(r *http.Request) string {
	if u := auth.FromCtx(r.Context()); u != nil {
		return u.Username
	}
	return ""
}

// ---- auth ----

func (s *Server) tooManyFails(ip string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if s.loginFail == nil {
		s.loginFail = map[string][]time.Time{}
	}
	var keep []time.Time
	for _, t := range s.loginFail[ip] {
		if time.Since(t) < 5*time.Minute {
			keep = append(keep, t)
		}
	}
	s.loginFail[ip] = keep
	return len(keep) >= 10
}

func (s *Server) noteFail(ip string) {
	s.loginMu.Lock()
	s.loginFail[ip] = append(s.loginFail[ip], time.Now())
	s.loginMu.Unlock()
}

// auditIP: adres połączenia + (informacyjnie) X-Forwarded-For / X-Real-IP, jeśli przed aplikacją stoi proxy.
func auditIP(r *http.Request, ip string) map[string]string {
	m := map[string]string{"ip": ip}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		m["forwarded_for"] = v
	} else if v := r.Header.Get("X-Real-IP"); v != "" {
		m["forwarded_for"] = v
	}
	m["user_agent"] = r.UserAgent()
	return m
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	ip := clientIP(r)
	// blokada per (adres, login): za Dockerem wszyscy klienci mają ten sam adres bramy, więc sam adres
	// blokowałby wszystkich naraz, gdy jedna osoba kilka razy pomyli hasło
	key := ip + "|" + strings.ToLower(strings.TrimSpace(in.Username))
	if s.tooManyFails(key) {
		fail(w, 429, "zbyt wiele nieudanych prób, spróbuj za kilka minut")
		return
	}
	tok, u, err := s.A.Login(strings.TrimSpace(in.Username), in.Password)
	if err != nil {
		s.noteFail(key)
		s.S.Audit(in.Username, "login.fail", "", auditIP(r, ip))
		fail(w, 401, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "asi_token", Value: tok, Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	s.S.Audit(u.Username, "login", "", auditIP(r, ip))
	out := map[string]any{"user": meJSON(u)}
	if r.URL.Query().Get("bearer") == "1" {
		out["token"] = tok // tylko dla klientów API (nagłówek Authorization: Bearer); przeglądarka używa ciasteczka HttpOnly
	}
	writeJSON(w, 200, out)
}

// changeOwnPassword: każdy użytkownik zmienia własne hasło (z podaniem obecnego). Wcześniejsze sesje tracą ważność,
// a bieżąca dostaje nowy token.
func (s *Server) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	me := auth.FromCtx(r.Context())
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := readJSON(r, &in); err != nil || me == nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	if utf8.RuneCountInString(in.New) < 10 {
		fail(w, 400, "nowe hasło musi mieć co najmniej 10 znaków")
		return
	}
	key := "pw:" + me.Username // limit prób jak przy logowaniu (zgadywanie obecnego hasła z przejętej sesji)
	if s.tooManyFails(key) {
		fail(w, 429, "zbyt wiele nieudanych prób, spróbuj za kilka minut")
		return
	}
	if _, _, err := s.A.Login(me.Username, in.Current); err != nil {
		s.noteFail(key)
		fail(w, 403, "obecne hasło jest niepoprawne")
		return
	}
	_, _ = s.S.DB.Exec(`UPDATE users SET pass_hash=?, token_gen=COALESCE(token_gen,0)+1 WHERE id=?`, hashPw(in.New), me.ID)
	tok, _, err := s.A.Login(me.Username, in.New)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "asi_token", Value: tok, Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	s.S.Audit(me.Username, "user.password_self", me.Username, nil)
	out := map[string]any{"ok": true}
	if r.URL.Query().Get("bearer") == "1" {
		out["token"] = tok // klient API (Bearer) dostaje nowy token
	}
	writeJSON(w, 200, out)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("asi_token"); err == nil && c.Value != "" {
		s.A.Revoke(c.Value)
	} else if h := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); h != "" {
		s.A.Revoke(h)
	}
	http.SetCookie(w, &http.Cookie{Name: "asi_token", Value: "", Path: "/", HttpOnly: true, MaxAge: -1, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func meJSON(u *auth.User) map[string]any {
	return map[string]any{"id": u.ID, "username": u.Username, "role": u.Role, "permissions": u.PermList()}
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, meJSON(auth.FromCtx(r.Context())))
}

// ---- użytkownicy i role ----

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := s.S.DB.Query(`SELECT u.id,u.username,r.name,u.disabled,u.created_at,u.last_login FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.id`)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var name, role, created, last string
		var dis int
		_ = rows.Scan(&id, &name, &role, &dis, &created, &last)
		out = append(out, map[string]any{"id": id, "username": name, "role": role, "disabled": dis == 1, "created_at": created, "last_login": last})
	}
	writeJSON(w, 200, out)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password, Role string }
	if err := readJSON(r, &in); err != nil || strings.TrimSpace(in.Username) == "" {
		fail(w, 400, "podaj login, hasło i rolę")
		return
	}
	if utf8.RuneCountInString(in.Password) < 10 { // jedna zasada dla haseł ustawianych w UI/API (konta demo z seeda są wyjątkiem)
		fail(w, 400, "hasło musi mieć co najmniej 10 znaków")
		return
	}
	id, err := s.A.CreateUser(in.Username, in.Password, in.Role)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.S.Audit(user(r), "user.create", in.Username, map[string]string{"role": in.Role})
	writeJSON(w, 201, map[string]any{"id": id})
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	var in struct {
		Role     string `json:"role"`
		Password string `json:"password"`
		Disabled *bool  `json:"disabled"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "niepoprawne dane")
		return
	}
	me := auth.FromCtx(r.Context())
	if in.Role != "" {
		var rid int64
		if err := s.S.DB.QueryRow(`SELECT id FROM roles WHERE name=?`, in.Role).Scan(&rid); err != nil {
			fail(w, 400, "nieznana rola")
			return
		}
		if id == me.ID && in.Role != me.Role {
			fail(w, 400, "nie możesz zmienić własnej roli")
			return
		}
		_, _ = s.S.DB.Exec(`UPDATE users SET role_id=? WHERE id=?`, rid, id)
	}
	if in.Password != "" {
		if utf8.RuneCountInString(in.Password) < 10 {
			fail(w, 400, "hasło musi mieć co najmniej 10 znaków")
			return
		}
		// zmiana hasła unieważnia wszystkie wcześniejsze sesje tego konta
		_, _ = s.S.DB.Exec(`UPDATE users SET pass_hash=?, token_gen=COALESCE(token_gen,0)+1 WHERE id=?`, hashPw(in.Password), id)
	}
	if in.Disabled != nil {
		if id == me.ID && *in.Disabled {
			fail(w, 400, "nie możesz zablokować własnego konta")
			return
		}
		_, _ = s.S.DB.Exec(`UPDATE users SET disabled=? WHERE id=?`, boolInt(*in.Disabled), id)
	}
	s.S.Audit(user(r), "user.update", strconv.FormatInt(id, 10), map[string]any{"role": in.Role, "disabled": in.Disabled, "password_changed": in.Password != ""})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	if id == auth.FromCtx(r.Context()).ID {
		fail(w, 400, "nie możesz usunąć własnego konta")
		return
	}
	_, _ = s.S.DB.Exec(`DELETE FROM users WHERE id=?`, id)
	s.S.Audit(user(r), "user.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	rows, err := s.S.DB.Query(`SELECT id,name,description,builtin FROM roles ORDER BY id`)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var name, desc string
		var b int
		_ = rows.Scan(&id, &name, &desc, &b)
		perms := []string{}
		for p := range s.A.RolePerms(id) {
			perms = append(perms, p)
		}
		out = append(out, map[string]any{"id": id, "name": name, "description": desc, "builtin": b == 1, "permissions": perms})
	}
	writeJSON(w, 200, out)
}

func (s *Server) listPermissions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, auth.AllPermissions)
}

func (s *Server) saveRole(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	var in struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := readJSON(r, &in); err != nil || strings.TrimSpace(in.Name) == "" {
		fail(w, 400, "podaj nazwę roli")
		return
	}
	valid := map[string]bool{}
	for _, p := range auth.AllPermissions {
		valid[p] = true
	}
	for _, p := range in.Permissions {
		if !valid[p] {
			fail(w, 400, "nieznane uprawnienie: "+p)
			return
		}
	}
	if id != 0 {
		var b int
		_ = s.S.DB.QueryRow(`SELECT builtin FROM roles WHERE id=?`, id).Scan(&b)
		if b == 1 {
			fail(w, 400, "role wbudowane są chronione: utwórz własną rolę")
			return
		}
		_, _ = s.S.DB.Exec(`UPDATE roles SET name=?, description=? WHERE id=?`, in.Name, in.Description, id)
	} else {
		res, err := s.S.DB.Exec(`INSERT INTO roles(name,description) VALUES(?,?)`, in.Name, in.Description)
		if err != nil {
			fail(w, 400, "rola o tej nazwie już istnieje")
			return
		}
		id, _ = res.LastInsertId()
	}
	_, _ = s.S.DB.Exec(`DELETE FROM role_permissions WHERE role_id=?`, id)
	for _, p := range in.Permissions {
		_, _ = s.S.DB.Exec(`INSERT INTO role_permissions(role_id,perm) VALUES(?,?)`, id, p)
	}
	s.A.Invalidate()
	s.S.Audit(user(r), "role.save", in.Name, in.Permissions)
	writeJSON(w, 200, map[string]any{"id": id})
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	var b, n int
	_ = s.S.DB.QueryRow(`SELECT builtin FROM roles WHERE id=?`, id).Scan(&b)
	_ = s.S.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE role_id=?`, id).Scan(&n)
	if b == 1 || n > 0 {
		fail(w, 400, "nie można usunąć roli wbudowanej ani przypisanej do użytkowników")
		return
	}
	_, _ = s.S.DB.Exec(`DELETE FROM roles WHERE id=?`, id)
	s.A.Invalidate()
	s.S.Audit(user(r), "role.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
