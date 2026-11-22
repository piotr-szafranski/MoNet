package httpprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// Serwer odpowiadający 200 na wszystko nie może dawać trafień ścieżek; prawdziwa treść /.env musi zostać.
func TestSoft404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			_, _ = w.Write([]byte("DB_PASSWORD=sekret\nAPP_KEY=base64:xyz"))
			return
		}
		_, _ = w.Write([]byte("<html><title>Web Viewer</title><body>login " + r.URL.Path + "</body></html>"))
	}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pn, _ := strconv.Atoi(port)
	p := New(NewLimiter(100), 3*time.Second, func(string) bool { return true }, nil)
	res := &Result{Scheme: "http"}
	p.FetchPaths(context.Background(), res, host, pn, "", []string{"/admin", "/.git/HEAD", "/.env"})
	if !res.SoftNotFound {
		t.Fatal("nie wykryto soft-404")
	}
	if _, ok := res.Paths["/admin"]; ok {
		t.Fatal("/admin z odpowiedzi soft-404 nie powinien być trafieniem")
	}
	if _, ok := res.Paths["/.env"]; !ok {
		t.Fatal("prawdziwa treść /.env zgubiona")
	}
}
