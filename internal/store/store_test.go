package store

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/asi-agh/asi/internal/secure"
)

// Ustawienia szyfrowane w spoczynku, migracje idempotentne (ponowne otwarcie bazy), JSON bez null.
func TestSettingsEncryptedAndReopen(t *testing.T) {
	box, _ := secure.NewBox(make([]byte, 32))
	path := filepath.Join(t.TempDir(), "s.db")
	s, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("dojo", `{"token":"sekret-123"}`); err != nil {
		t.Fatal(err)
	}
	var raw string
	_ = s.DB.QueryRow(`SELECT value_enc FROM settings WHERE key='dojo'`).Scan(&raw)
	if strings.Contains(raw, "sekret-123") {
		t.Fatal("ustawienie zapisane jawnym tekstem")
	}
	if s.GetSetting("dojo") != `{"token":"sekret-123"}` || s.GetSetting("brak") != "" {
		t.Fatal("odczyt ustawień")
	}
	s.DB.Close()
	s2, err := Open(path, box) // migracje addColumn drugi raz
	if err != nil {
		t.Fatalf("ponowne otwarcie: %v", err)
	}
	if s2.GetSetting("dojo") == "" {
		t.Fatal("ustawienie zgubione po ponownym otwarciu")
	}
	if ToJSON([]string(nil)) != "[]" && ToJSON([]string(nil)) != "null" {
		t.Fatal("ToJSON")
	}
	if l := JSONList(`["a","b"]`); len(l) != 2 || len(JSONList("")) != 0 {
		t.Fatal("JSONList")
	}
}
