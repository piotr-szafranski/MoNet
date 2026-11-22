package dojo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Pierwsza próba 503, druga OK: wysyłka ma się udać; scan_date w UTC.
func TestReimportRetry(t *testing.T) {
	var n int32
	var date string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/reimport-scan/") {
			_, _ = w.Write([]byte(`{"results":[]}`))
			return
		}
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(503)
			return
		}
		_ = r.ParseMultipartForm(1 << 20)
		date = r.FormValue("scan_date")
		_, _ = w.Write([]byte(`{"test":1}`))
	}))
	defer srv.Close()
	if _, err := Reimport(context.Background(), Settings{URL: srv.URL, Token: "x", Product: "P"}, nil, "t"); err != nil {
		t.Fatalf("ponowienie nie zadziałało: %v", err)
	}
	if n != 2 {
		t.Fatalf("oczekiwano 2 prób, było %d", n)
	}
	if date != time.Now().UTC().Format("2006-01-02") {
		t.Fatalf("scan_date nie w UTC: %s", date)
	}
}
