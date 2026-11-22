package secure

import (
	"strings"
	"testing"
)

func TestSealOpen(t *testing.T) {
	b, _ := NewBox([]byte("0123456789abcdef0123456789abcdef"))
	c := b.Seal("Set-Cookie: sesja=tajne")
	if !strings.HasPrefix(c, prefix) || strings.Contains(c, "tajne") {
		t.Fatal("brak szyfrowania")
	}
	if c == b.Seal("Set-Cookie: sesja=tajne") {
		t.Fatal("nonce musi być losowy")
	}
	if p, err := b.Open(c); err != nil || p != "Set-Cookie: sesja=tajne" {
		t.Fatal("odszyfrowanie")
	}
	other, _ := NewBox([]byte("ffffffffffffffffffffffffffffffff"))
	if _, err := other.Open(c); err == nil {
		t.Fatal("inny klucz nie może odszyfrować")
	}
	if !CheckPassword(HashPassword("haslo123!"), "haslo123!") || CheckPassword(HashPassword("a"), "b") {
		t.Fatal("argon2id")
	}
}
