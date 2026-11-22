// Package secure: szyfrowanie pól w spoczynku (AES-256-GCM), HMAC do wyszukiwania i hashowanie haseł (argon2id).
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const prefix = "enc:v1:"

// Box szyfruje i odszyfrowuje wartości pól. Klucz główny nigdy nie trafia do bazy.
type Box struct {
	aead    cipher.AEAD
	hmacKey []byte
}

// LoadKey: ASI_MASTER_KEY (base64, 32 B) albo plik ASI_MASTER_KEY_FILE; w trybie dev generuje plik klucza.
func LoadKey(envKey, keyFile string, allowGenerate bool) ([]byte, bool, error) {
	if envKey != "" {
		k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envKey))
		if err != nil || len(k) != 32 {
			return nil, false, errors.New("ASI_MASTER_KEY musi być base64 z 32 bajtów")
		}
		return k, false, nil
	}
	if keyFile != "" {
		if b, err := os.ReadFile(keyFile); err == nil {
			k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
			if err != nil || len(k) != 32 {
				return nil, false, fmt.Errorf("niepoprawny plik klucza %s", keyFile)
			}
			return k, false, nil
		}
		if allowGenerate {
			k := make([]byte, 32)
			if _, err := rand.Read(k); err != nil {
				return nil, false, err
			}
			if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(k)+"\n"), 0o600); err != nil {
				return nil, false, err
			}
			return k, true, nil
		}
	}
	return nil, false, errors.New("brak klucza głównego (ASI_MASTER_KEY lub ASI_MASTER_KEY_FILE)")
}

func NewBox(master []byte) (*Box, error) {
	derive := func(info string) []byte {
		out := make([]byte, 32)
		r := hkdf.New(sha256.New, master, nil, []byte(info))
		_, _ = r.Read(out)
		return out
	}
	block, err := aes.NewCipher(derive("asi-field-encryption"))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead, hmacKey: derive("asi-field-hmac")}, nil
}

// Seal szyfruje tekst. Pusty tekst zostaje pusty (brak danych do ochrony).
func (b *Box) Seal(plain string) string {
	if plain == "" {
		return ""
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	ct := b.aead.Seal(nonce, nonce, []byte(plain), nil)
	return prefix + base64.RawStdEncoding.EncodeToString(ct)
}

func (b *Box) Open(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if !strings.HasPrefix(v, prefix) {
		return "", errors.New("wartość nie jest zaszyfrowana")
	}
	raw, err := base64.RawStdEncoding.DecodeString(v[len(prefix):])
	if err != nil {
		return "", err
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("uszkodzony szyfrogram")
	}
	pt, err := b.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// MustOpen zwraca pusty tekst przy błędzie (np. uszkodzony rekord), nie przerywa listowania.
func (b *Box) MustOpen(v string) string {
	s, err := b.Open(v)
	if err != nil {
		return ""
	}
	return s
}

// Blind zwraca deterministyczny HMAC do wyszukiwania po polu zaszyfrowanym.
func (b *Box) Blind(v string) string {
	m := hmac.New(sha256.New, b.hmacKey)
	m.Write([]byte(strings.ToLower(strings.TrimSpace(v))))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// ---- hasła ----

func HashPassword(pw string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	h := argon2.IDKey([]byte(pw), salt, 2, 64*1024, 2, 32)
	return fmt.Sprintf("argon2id$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(h))
}

func CheckPassword(stored, pw string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[1])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, 2, 64*1024, 2, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func RandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
