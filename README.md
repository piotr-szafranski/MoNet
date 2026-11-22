# MoNet (Monitoring Network)

Prototyp systemu do **cyklicznego discovery scan dużej infrastruktury** (ponad 10 000 adresów IP) dla Centrum
Bezpieczeństwa Informacji AGH. MoNet wykrywa aktywne hosty, identyfikuje usługi, pobiera informacje HTTP/HTTPS
(tytuł, kod, nagłówki, ciasteczka, certyfikat TLS, przekierowania), rozpoznaje technologie, CMS-y, urządzenia IoT,
panele administracyjne i środowiska testowe, a także rejestruje zmiany w czasie: nowe, znikające i zmienione usługi
oraz hosty niestabilne.

Projekt zrealizowany na HackNation 2026 (zadanie AGH „Attack Surface Intelligence”).

**Testy na szablonach labu AGH** (`docs/TEST_LAB_AGH.md`): custom-network, modern i modern-proxy, po 100% pokrycia
listy kontrolnej (hosty, usługi, technologie, panele, artefakty, HTTP/TLS, znikające i powracające usługi, opóźnienia).

## Najważniejsze funkcje

| Wymaganie | Jak to robi MoNet |
|---|---|
| Wczytanie IP, CIDR, domen | formularz ręczny + import CSV/JSON (ta sama walidacja i przetwarzanie), zakresy `10.0.0.1-50` |
| Bezpieczny, wielowątkowy skan | nmap w workerach (`-sn` → `-sS/-sT -sV`), globalny limit pakietów/s, limit zapytań HTTP/s, timeouty, wykluczenia, strażnik zakresu |
| Podział na optymalne podgrupy | planer dzieli adresy na podgrupy i dopasowuje ich rozmiar do zmierzonego tempa (cel: N sekund na podgrupę) |
| Czas trwania skanu | czas, tempo (IP/s), ETA, historia podgrup; szacowanie czasu przed uruchomieniem na podstawie historii |
| Wyniki na bieżąco | baza urządzeń (hosty, usługi, stany) aktualizowana po każdej podgrupie adresów, w trakcie skanu, a nie dopiero na jego końcu |
| Nieosiągnięte końcówki | znane hosty, które nie odpowiedziały (także po ponownym pomiarze), i cele podane jako pojedyncze IP zapisują się jako `missing`/`unreachable` z czasem ostatniej próby; kolejny skan sprawdza je w pierwszej kolejności |
| Doskanowanie w ciągu dnia | poza głównym oknem (np. 22–06) co N minut skaner sprawdza małą paczkę (np. 16) nieosiągniętych końcówek z 1/10 limitu tempa; co odpowie, od razu trafia do bazy, a pomiary zasilają wykrywanie zależności od pory dnia |
| Okna czasowe i częstotliwość | harmonogram (co N minut, okno od–do, dni tygodnia, okna przez północ); po końcu okna skan jest zatrzymywany i **wznawiany od miejsca przerwania** w kolejnym oknie |
| Aktywne hosty i usługi | discovery (ICMP/TCP/ARP) + wykrywanie wersji usług nmapa |
| HTTP/HTTPS | tytuł, kod, nagłówki, ciasteczka (Secure/HttpOnly/SameSite), certyfikat (podmiot, SAN, wystawca, ważność, self-signed), przekierowania (tylko w zakresie), favicon mmh3 |
| Technologie, CMS, IoT, staging, panele | 72 wbudowane sygnatury (plus własne i importowane z nuclei, Wappalyzer, CSV) z oceną pewności 0–100% i listą dowodów; zakładka **Technologie** z rozkładem wersji |
| Własne sygnatury | edytor YAML w UI, test na zebranych wynikach; **import z pliku**: format MoNet, szablony nuclei (tylko bezpieczne GET), Wappalyzer, CSV, z podglądem i ostrzeżeniami; eksport YAML/JSON |
| **Uczenie od analityka** | kreator **„Naucz system”** w szczegółach usługi: z tytułu, favicony, nagłówków, ciasteczek, banera lub ścieżki (np. `/dashboard/`) tworzy własną sygnaturę, testuje ją na wynikach i zapisuje; kolejny skan rozpoznaje podobne usługi w całej sieci |
| Technologia z banera | produkt z `nmap -sV` lub nagłówka `Server` trafia do technologii także bez sygnatury |
| Czas odpowiedzi | pomiar pierwszej odpowiedzi HTTP, kolumna w wynikach, flaga „wolna odpowiedź” (≥ 500 ms), zmiana czasu w porównaniu skanów |
| HTTP + HTTPS na jednym porcie | wykrywane oba schematy; flaga „HTTP odsłonięty obok HTTPS”, gdy HTTP nie przekierowuje na HTTPS; port TLS bez certyfikatu dla IP oznaczany „TLS bez certyfikatu (SNI)” |
| Kategorie wyników | szczegóły skanu grupują usługi wg rozpoznania (IoT, staging, panele, CMS, bazy, zdalny dostęp…), liczba hostów na kategorię |
| Klasa (priorytet analityczny) | **reguły klasy** edytowalne w UI: wagi sygnatur, reguł ogólnych (wygasły certyfikat, logowanie bez TLS…) i portów; nowe porty dopisywane automatycznie „do oceny”; przeliczenie bez ponownego skanu; pokrycie „X z N reguł” |
| Porównanie skanów | diff nowe / znikające / zmienione (pole po polu), tylko na portach i adresach objętych oboma skanami |
| Hosty niestabilne | ponowny pomiar hostów, które przestały odpowiadać; stany active / missing / unstable / gone (po N skanach); historia obecności; histogram pory dnia |
| RBAC | role w bazie (własne role), wbudowane: **Administrator**, **Operator** (dodawanie, usuwanie, modyfikacja), **Analityk** (modyfikacja i odczyt), **Obserwator** (odczyt); sprawdzane w API |
| Edycja danych | edycja celów, konfiguracji, wyników skanów (z audytem) i **adnotacji**: tagi, notatki, właściciel, ważność, fałszywy alarm. Adnotacje są zachowywane przy kolejnych skanach |
| Szyfrowanie w spoczynku | AES-256-GCM dla pól wrażliwych (banery, nagłówki, ciasteczka, tytuły, certyfikaty, notatki, token DefectDojo); hasła argon2id |
| Import / eksport | import wyników: XML nmapa, JSON/CSV MoNet; eksport JSON/CSV (skan, inwentarz, cele, diff) |
| DefectDojo | eksport jako findingi informacyjne (Generic Findings Import) przez API v2; **reimport** do stałego testu (nowe dochodzą, zniknięte są zamykane, powracające przywracane); automatyczny eksport po skanie; historia wysyłek z licznikami zmian; zweryfikowane seriami testów (`docs/DEFECTDOJO_TESTY.md`, `docs/DEFECTDOJO_SERIA.md`) |
| Dashboard | skan w toku z paskiem postępu, kafle (hosty, usługi, ciekawe, niestabilne), wykryte różnice, aktywne flagi, najciekawsze usługi pogrupowane według klasy i flag |
| Historia i niedostępne końcówki | zakładka **Skany**: przebiegi pogrupowane według okresów i dat oraz lista **niedostępnych końcówek** (brak odpowiedzi, nieosiągalne, niestabilne) z ostrzeżeniem dla końcówek niewidzianych od ≥ 3 dni |

## Interfejs

Ciemny, „metaliczny” interfejs z cienkimi liniami podziału. Zakładki: Dashboard, Cele, Skany (historia i konfiguracje
z doskanerem), Usługi (kategorie; widoki Aktywne / Niestabilne / Niedostępne), Hosty (te same widoki), Technologie,
Zmiany (z osią czasu), Sygnatury, Reguły klasy, Import / eksport (wraz z DefectDojo), Administracja (użytkownicy,
role, polityka skanera, dziennik logów). Zrzuty ekranów są
w prezentacji.

## Szybki start

Wymagania: Docker + Docker Compose (Linux; alternatywnie Podman).

```bash
printf "ASI_MASTER_KEY=$(openssl rand -base64 32)\nASI_ADMIN_PASSWORD=<hasło, min. 10 znaków>\n" > .env
docker compose up -d --build
# UI: http://localhost:8080, logowanie: admin + hasło z .env
```

Produkcyjny `docker-compose.yml` wymaga `ASI_ADMIN_PASSWORD` i domyślnie nie tworzy kont demo (włącza je `ASI_DEMO_USERS=1`
w `.env`). Lab (`docker-compose.lab.yml`) ma konta demo dla 4 ról: admin / admin123!, operator / operator123!,
analityk / analityk123!, obserwator / obserwator123!. Własne hasło każdy zmienia w menu konta (awatar → Zmień hasło);
zmiana wylogowuje pozostałe sesje.

### Lab testowy (sieć /18: 16 381 adresów do skanu, ~1500 symulowanych hostów)

```bash
# 1) odizolowana sieć 10.66.0.0/18 + symulator infrastruktury + kilka prawdziwych usług
docker-compose -p asi-lab -f lab/docker-compose.yml up -d --build
# 2) MoNet podłączony do sieci labu (UI na porcie 8095)
CGO_ENABLED=0 go build -o bin/asi ./cmd/asi && CGO_ENABLED=0 go build -o bin/labsim ./cmd/labsim
docker-compose -p asi -f docker-compose.lab.yml up -d --build
```

Symulator (`cmd/labsim`) wystawia na aliasach IP 30 profili (CMS-y, kamery, drukarki, routery, panele, staging,
SSH/FTP/MySQL/Redis/Telnet, odsłonięte `.git`/`.env`, wygasłe certyfikaty). Ma też hosty **niestabilne** (znikają co
fazę), **zależne od pory dnia** i **zmieniające się** między skanami (wersje, nowe/znikające porty). Endpoint `/truth`
zwraca rzeczywisty stan, a `scripts/accuracy.py` liczy precyzję i czułość skanera.

## Jak używać

1. **Cele**: wpisz zakresy lub zaimportuj CSV/JSON, oznacz tagami.
2. **Skany → Nowa konfiguracja**: podaj **porty** (lista/zakresy albo preset), limity tempa, liczbę workerów,
   ewentualnie harmonogram z oknem czasowym. „Szacuj czas” pokazuje przewidywany czas skanu.
3. **Uruchom**: postęp, tempo, rozmiary podgrup i ETA widać na żywo.
4. **Dashboard / Usługi / Hosty**: przegląd wyników, filtry, szczegóły usługi z dowodami i adnotacje.
5. **Zmiany**: porównanie dwóch przebiegów.
6. **Sygnatury**: własne reguły detekcji i import gotowych zestawów; **Reguły klasy**: wagi priorytetów.
7. **Import / eksport**: wymiana danych, DefectDojo i historia wysyłek.

Pełna instrukcja testu na środowisku dostarczonym przez organizatora: [docs/INSTRUKCJA_LAB_AGH.md](docs/INSTRUKCJA_LAB_AGH.md).

## API dla integracji

REST/JSON pod `/api`. Przeglądarka loguje się ciasteczkiem HttpOnly. Klient skryptowy pobiera token przez
`POST /api/auth/login?bearer=1` (`{"username","password"}`) i wysyła go w nagłówku `Authorization: Bearer <token>`.
Token wygasa po 12 h; wylogowanie (`POST /api/auth/logout`) i zmiana hasła unieważniają go od razu.

## Bezpieczeństwo działania skanera

- Skanowane są wyłącznie adresy z listy celów (minus wykluczenia); przekierowania HTTP poza zakres są tylko zapisywane.
- Sondy HTTP to wyłącznie `GET` na stronę główną, `/favicon.ico` i ścieżki z sygnatur, bez logowania i bez payloadów.
- Ścieżki potwierdzające technologię (np. `/wp-login.php`) są sprawdzane tylko wtedy, gdy strona główna już na nią wskazuje.
  Ścieżki ogólne (`/admin`, `/.env`, `/.git/HEAD`, `/server-status`) są domyślnie sprawdzane na każdej usłudze HTTP;
  administrator może je wyłączyć w **Administracja → Polityka skanera**.
- Wykrywanie soft-404: przed sprawdzeniem ścieżek skaner pyta o nieistniejący adres. Jeśli serwer odpowiada „200” na
  wszystko, trafienia identyczne z tą odpowiedzią są odrzucane (brak fałszywych `/admin` i `/.env` na urządzeniach wbudowanych).
- **Polityka domyślna** (zanim administrator zapisze własną): tylko sieci prywatne (10/8, 172.16/12, 192.168/16, 100.64/10),
  maks. 5 000 pakietów/s, 100 zapytań HTTP/s, 8 podgrup. Cel publiczny wymaga świadomego dopisania sieci przez administratora.
- **Polityka skanera** (administrator): twarde limity tempa pakietów, zapytań HTTP/s i równoległości oraz lista dozwolonych
  sieci. Konfiguracja operatora nie może ich przekroczyć, a skan z adresem spoza listy nie wystartuje (sprawdzane także przy wznowieniu).
- Intensywność: limit pakietów/s (`nmap --max-rate`, dzielony na workery), limit zapytań HTTP/s (token bucket), timeouty hosta, ponowienia.
- Poprawki analityka (produkt, wersja, technologie, klasa, notatka) zapisywane są na poziomie usługi `ip:port/proto`
  i nakładane na wynik każdego kolejnego skanu, doskanowania i importu; usługa oznaczona jako fałszywy alarm nie trafia do DefectDojo.
- Logowanie: argon2id, blokada po serii nieudanych prób na login (bez ufania nagłówkom `X-Forwarded-For` od klienta),
  wylogowanie unieważnia token po stronie serwera. Eksport CSV jest chroniony przed wstrzyknięciem formuł do arkusza.
- Wysyłka do DefectDojo: `scan_date` w UTC, ponowienia przy błędach sieci, 429 i 5xx.
- Identyfikacja w nagłówku `User-Agent: MoNet-DiscoveryScanner/1.0`, pełny dziennik audytu działań użytkowników.

## Architektura

```
React (Vite, Tailwind) ──REST/JSON──▶ asi (Go, jeden plik binarny)
                                       ├─ api/        RBAC, CRUD, import/eksport
                                       ├─ scheduler/  okna czasowe, wznawianie
                                       ├─ scan/       planer podgrup, workery, stany hostów
                                       ├─ nmap/       discovery + usługi (XML)
                                       ├─ httpprobe/  HTTP/TLS, favicon, ścieżki
                                       ├─ sig/        silnik sygnatur YAML
                                       ├─ diff/       porównanie skanów
                                       ├─ dojo/       DefectDojo API v2
                                       └─ store/      SQLite (WAL) + AES-256-GCM
```

Szczegóły: [docs/ARCHITEKTURA.md](docs/ARCHITEKTURA.md), formaty danych i import sygnatur: [docs/FORMATY.md](docs/FORMATY.md),
DefectDojo: [docs/DEFECTDOJO.md](docs/DEFECTDOJO.md), pomiary: [docs/POMIARY.md](docs/POMIARY.md).

### Weryfikacja obrazu produkcyjnego

`docker build` od zera i uruchomienie z czystą bazą (`deploy/prodtest.yml`) zostały sprawdzone: konta tworzą się
przy starcie, nmap jest w obrazie, a UI i API działają.

## Zmienne środowiskowe

| Zmienna | Opis | Domyślnie |
|---|---|---|
| `ASI_MASTER_KEY` | klucz szyfrowania (base64, 32 B) | – (wymagany w produkcji) |
| `ASI_MASTER_KEY_FILE` | alternatywnie plik z kluczem (np. docker secret) | `/data/master.key` |
| `ASI_ALLOW_KEYGEN` | generuj klucz, jeśli brak (tylko dev) | `1` |
| `ASI_ADDR` / `ASI_DATA` | adres nasłuchu / katalog danych | `:8080` / `./data` |
| `ASI_ADMIN_USER` / `ASI_ADMIN_PASSWORD` | konto administratora tworzone przy pierwszym starcie | `admin` / `admin123!` |
| `ASI_DEMO_USERS` | konta demo dla 4 ról | `0` w `docker-compose.yml`, `1` w labie |
| `ASI_NMAP` | ścieżka do nmapa | `nmap` |
| `ASI_NO_ARP` | wyłącz ARP ping (symulacja sieci routowanej) | `0` |
| `ASI_COOKIE_SECURE` | ciasteczko sesji tylko po HTTPS | `0` |

## Użyte oprogramowanie i licencje

Wszystkie komponenty są darmowe i otwarte; pełna lista: [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
Nmap (Nmap Public Source License) jest uruchamiany jako osobny program, nie jest wkompilowany w MoNet.

Projekt powstał z pomocą asystenta AI (Claude Code) jako narzędzia programistycznego; aplikacja nie korzysta z żadnych płatnych API.
