# Zadania dla autopilota (noc 21/22.11)

Format: `- [ ]` do zrobienia, `- [x]` zrobione, `- [!]` zablokowane. Autopilot bierze zawsze pierwsze `- [ ]`.

- [ ] **Pomiary do dokumentacji.** Na podstawie dwóch ostatnich zakończonych skanów labu napisz `docs/POMIARY.md`:
  czas skanu, liczba adresów, hosty, usługi, średnie tempo (IP/s), rozkład rozmiarów i czasów podgrup (z
  `GET /api/scans/{id}`), wynik `scripts/accuracy.py` (pobierz `/truth` z symulatora poleceniem
  `docker exec asi-lab-sim wget -qO- http://127.0.0.1:9999/truth > /tmp/truth.json`), wynik `scripts/rbac_test.py`.
  Kryterium: plik zawiera tabelę z liczbami i krótką interpretację (po polsku), bez zmyślonych wartości.

- [ ] **Test jednostkowy diffu.** Dodaj `internal/diff/diff_test.go`: baza w pamięci (`store.Open(":memory:"…)`
  albo plik w `t.TempDir()`), dwa sztuczne skany (bloki, scan_hosts, observations przez `scan.InsertObservation`),
  sprawdź wykrycie: nowej usługi, znikającej usługi, zmiany wersji (pole „wersja”), nowego i znikającego hosta oraz
  to, że port spoza wspólnej listy portów NIE jest raportowany jako zniknięty.
  Kryterium: `go test ./internal/diff/` przechodzi.

- [ ] **Test stanów hostów i harmonogramu okna.** Dodaj test w `internal/scan/` korzystający z bazy w `t.TempDir()`:
  `applyStates` wywołane 4 razy dla hosta obecnego w skanach 1, 2 i nieobecnego w 3, 4 (gone_after=2) daje stany
  active → active → missing → gone. Kryterium: `go test ./internal/scan/` przechodzi.

- [ ] **Widok „Zmiany w czasie”.** Na stronie Dashboard (lub nowej zakładce na stronie Zmiany) dodaj oś czasu ostatnich
  10 zakończonych skanów: dla każdej pary kolejnych skanów liczby nowych/znikających/zmienionych usług
  (backend: nowy endpoint `GET /api/timeline?limit=10` liczący `diff.Compute` dla par; zabezpiecz uprawnieniem
  `results.read`). Kryterium: `go vet`, testy, `npx vite build` przechodzą; endpoint zwraca JSON.

- [ ] **Sygnatury: rozszerzenie i testy.** Dodaj do `internal/sig/builtin.yaml` co najmniej 10 nowych bezpiecznych
  sygnatur (np. Nextcloud, Roundcube, Zabbix, Proxmox, pfSense, Synology DSM, Fortinet (strona logowania),
  Cisco (strona logowania), Keycloak, MinIO, RabbitMQ management, SonarQube) na podstawie publicznie znanych
  cech (tytuł, nagłówki, ciasteczka, ścieżki) oraz test w `internal/sig/sig_test.go` z przykładowymi odpowiedziami
  dla 5 z nich. Nie kopiuj baz Wappalyzera (licencja GPL). Kryterium: testy przechodzą, sygnatur ≥ 75.

- [ ] **Scenariusz demo i treść prezentacji.** Napisz `docs/PREZENTACJA.md`: 10 slajdów (problem, rozwiązanie,
  architektura, discovery i podgrupy, fingerprinting i sygnatury, zmiany w czasie i hosty niestabilne,
  bezpieczeństwo skanera, RBAC i szyfrowanie, integracje i import/eksport, pomiary + licencje) oraz scenariusz
  demo na 2 minuty krok po kroku w UI. Używaj tylko faktów z repo (README, docs, POMIARY).

- [ ] **Obraz produkcyjny.** Zbuduj `docker build -t asi-prod-test .` NIE jest dozwolone przez autopilota, więc zamiast
  tego sprawdź statycznie `Dockerfile` (ścieżki COPY, outDir Vite = `internal/api/webdist`, nazwa binarki) i opisz
  ewentualne poprawki w `logs/autopilot.md`. Kryterium: wpis w logu.

- [ ] **Porządki w UI.** Przejrzyj strony w `web/src/pages/` pod kątem: pustych stanów, polskich etykiet, spójnych
  przycisków, braku błędów w konsoli (`npx vite build` bez ostrzeżeń o błędach). Popraw drobne usterki.
  Kryterium: build przechodzi, commit z listą poprawek.
