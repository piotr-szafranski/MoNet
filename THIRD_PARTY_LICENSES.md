# Oprogramowanie zewnętrzne i licencje

Wszystkie komponenty są bezpłatne i otwarte. W produkcie nie ma bibliotek na licencjach GPL/AGPL; kod MoNet może być
przekazany na dowolnej licencji.

## Uruchamiane jako osobne programy

| Komponent | Licencja | Uwagi |
|---|---|---|
| Nmap 7.9x | Nmap Public Source License (NPSL) | darmowy, kod jawny; uruchamiany jako zewnętrzny proces (pakiet systemowy), nie jest wkompilowany w MoNet. Płatna licencja OEM dotyczy tylko dystrybucji zamkniętych produktów zawierających nmapa |
| Debian (obraz bazowy) | DFSG (różne otwarte licencje) | |
| Docker Engine / Docker Compose | Apache-2.0 | alternatywnie Podman (Apache-2.0). Uwaga: Docker Desktop (Windows/macOS) jest płatny dla dużych organizacji, a MoNet go nie wymaga |

## Backend (Go)

| Moduł | Licencja |
|---|---|
| Go (biblioteka standardowa, w tym crypto/aes, crypto/tls) | BSD-3-Clause |
| github.com/go-chi/chi/v5 | MIT |
| github.com/golang-jwt/jwt/v5 | MIT |
| golang.org/x/crypto (argon2, hkdf) | BSD-3-Clause |
| gopkg.in/yaml.v3 | MIT / Apache-2.0 |
| modernc.org/sqlite (+ modernc.org/libc, mathutil, memory) | BSD-3-Clause |
| SQLite | domena publiczna |
| github.com/dustin/go-humanize, google/uuid, mattn/go-isatty, ncruces/go-strftime, remyoudompheng/bigfft | MIT / BSD-3-Clause (zależności pośrednie sterownika SQLite) |

## Frontend

| Pakiet | Licencja |
|---|---|
| React 18, react-dom | MIT |
| react-router-dom 6 | MIT |
| lucide-react (ikony) | ISC |
| @fontsource/ibm-plex-sans, @fontsource/ibm-plex-mono (wcześniej inter, jetbrains-mono, manrope) | SIL OFL 1.1 (fonty serwowane lokalnie, bez CDN) |
| Vite 5, @vitejs/plugin-react | MIT |
| Tailwind CSS 3, PostCSS, Autoprefixer | MIT |

## Lab testowy (poza produktem)

| Komponent | Licencja |
|---|---|
| nginx (obraz) | BSD-2-Clause |
| Apache httpd (obraz) | Apache-2.0 |
| Valkey (otwarta kontynuacja Redisa) | BSD-3-Clause |
| Alpine Linux (obraz symulatora) | MIT i inne otwarte |
| labsim (symulator infrastruktury) | część projektu MoNet |

## Integracje

| Usługa | Licencja |
|---|---|
| DefectDojo (integracja przez API v2) | BSD-3-Clause |

## Sygnatury

Wbudowane sygnatury (`internal/sig/builtin.yaml`) zostały napisane od podstaw na potrzeby projektu. Nie zawierają baz
na licencjach GPL (np. kopii baz Wappalyzera).

## Narzędzia deweloperskie

Claude Code (asystent AI) służył jako narzędzie programistyczne; nie jest częścią produktu.

## Skille asystenta AI (narzędzia pracy, nie część aplikacji)

| Skill | Źródło | Licencja | Użycie |
|---|---|---|---|
| find-skills | vercel-labs/skills | MIT | wyszukiwanie skilli |
| enterprise (design system) | bergside/awesome-design-skills (typeui.sh) | MIT | wytyczne stylu interfejsu |
| frontend-design-deslop | samber/cc-skills | MIT | metoda projektowania interfejsu, DESIGN.md |
| crypto-frontend-design | btc-vision/opnet-frontend-skills | brak deklaracji licencji | wyłącznie inspiracja; kod z tego skilla nie jest kopiowany do repozytorium |
