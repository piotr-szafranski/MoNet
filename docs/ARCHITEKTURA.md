# Architektura i decyzje techniczne

## Przepływ skanu

```
cele (IP/CIDR/zakresy/domeny) ──expand──▶ lista adresów (minus wykluczenia) ──▶ bloki po 64 IP (zapis w bazie)
                                                                                 │
           ┌──────────────────────── planer podgrup ◀── zmierzone tempo (IP/s) ──┘
           ▼
   worker 1..N (równolegle):
     1. nmap -sn            discovery (ICMP/TCP SYN/ACK na porty discovery, ARP w sieci lokalnej)
     2. nmap -sn (agresywnie) ponowny pomiar hostów wcześniej aktywnych, które nie odpowiedziały
     3. nmap -sS/-sT -sV    porty podane w konfiguracji, tylko na żywych hostach
     4. sonda HTTP/HTTPS    strona główna + favicon (+ ścieżki z sygnatur, dwuetapowo)
     5. sygnatury + ocena ciekawości → zapis obserwacji (blob zaszyfrowany AES-256-GCM)
           │
           ▼
   finalizacja: stany hostów i usług, historia obecności, histogram godzinowy → diff, dashboard, eksport
```

## Podział na optymalne podgrupy

Adresy są zapisywane w blokach po 64. Planer wydaje workerom podgrupy złożone z k bloków. Po każdej podgrupie liczy
tempo `IP/s` (średnia krocząca) i ustala `k = tempo × czas_docelowy / 64`, ograniczone do 64–4096 adresów. Dzięki temu
w gęstych segmentach (dużo żywych hostów i usług) podgrupy są mniejsze, a w pustych przestrzeniach większe. Każda
podgrupa trwa zbliżony czas, więc postęp, ETA i zatrzymanie na końcu okna są przewidywalne.

## Okna czasowe

Harmonogram sprawdza konfiguracje co 20 s. Skan startuje w oknie z deadline'em równym końcowi okna. Po jego
przekroczeniu kontekst jest anulowany (nmap dostaje SIGKILL), bloki w toku wracają do stanu `pending`, a skan
przechodzi w stan `paused`. W kolejnym oknie harmonogram wznawia **ten sam** skan od nieukończonych bloków; czas
trwania sumuje się z kolejnych okien (licznik `windows`). Po restarcie serwera przerwane skany też są wznawiane.

## Baza urządzeń aktualizowana na bieżąco

Każda podgrupa adresów zapisuje swoje wyniki w jednej transakcji: obserwacje, wynik discovery oraz aktualizację
inwentarza (`hosts`, `services`: pierwsze/ostatnie wykrycie, seria braków, historia, histogram godzin). Wyniki są
widoczne w UI i API po kilkudziesięciu sekundach od przeskanowania danego fragmentu sieci, a nie dopiero po
zakończeniu całego skanu (w odróżnieniu od narzędzi raportujących po fakcie).

## Nieosiągnięte końcówki i doskanowanie w ciągu dnia

Scenariusz CBI AGH: pełne skany w nocy (np. 22–06), gdy ruch w sieci jest mały. Część urządzeń działa jednak tylko
w godzinach pracy (np. 8–16), więc w nocy nie odpowiada, a pełnego skanu w dzień robić nie można.

1. Host znany z wcześniejszych skanów, który nie odpowiedział (także po ponownym pomiarze z większą liczbą sond),
   dostaje stan `missing` (a po K skanach `gone`). Cel podany jako pojedynczy adres, który nigdy nie odpowiedział,
   dostaje stan `unreachable`. Zapisujemy czas ostatniej próby (`last_checked`).
2. Kolejny skan sprawdza najpierw bloki zawierające takie końcówki.
3. **Doskanowanie** (opcja konfiguracji): poza głównym oknem, w osobnym oknie (np. 07–21), harmonogram co N minut
   bierze paczkę (np. 16) końcówek z ostatniego skanu, które nie odpowiedziały, zaczynając od sprawdzanych najdawniej.
   Skanuje je pełnym potokiem (discovery, usługi, HTTP, sygnatury) z 1 workerem i 1/10 limitu pakietów. Wyniki
   trafiają do dziennego skanu typu „Doskanowanie” i od razu do bazy urządzeń. Brak odpowiedzi w dzień nie zwiększa
   serii braków, ale liczy się do histogramu godzin, więc host aktywny tylko 8–16 zostaje oznaczony jako zależny od
   pory dnia.

## Hosty niestabilne i raportowanie zmian

- **Ponowny pomiar**: host aktywny wcześniej, który nie odpowiedział, jest natychmiast sprawdzany drugi raz
  z większą liczbą sond i prób. Dopiero brak odpowiedzi w drugim pomiarze jest liczony jako „miss”.
- **Stany**: `active` → `missing` (1..K-1 kolejnych braków) → `gone` (K braków, domyślnie 3, konfigurowalne);
  `unstable`, gdy w ostatnich 10 skanach obecność zmieniała się co najmniej 2 razy.
- **Pora dnia**: dla każdego hosta liczymy w 24 kubełkach godzinowych, ile razy był skanowany i ile razy odpowiedział.
  Wyraźny podział na godziny „zawsze” (≥ 75%) i „nigdy” (≤ 25%) jest raportowany jako zależność od pory dnia.
- **Diff** porównuje tylko adresy i porty objęte oboma skanami, więc zmiana listy portów lub zakresu nie generuje
  fałszywych „zniknięć”. Zmiana usługi jest wykrywana po odcisku (usługa, produkt, wersja, kod HTTP, tytuł,
  nagłówek Server, certyfikat, technologie) i raportowana pole po polu.

## Pewność identyfikacji technologii

Każdy matcher sygnatury ma wagę, a pewność to suma wag dopasowanych matcherów (maks. 100%). Przykład: WordPress
z meta generator (0.9) + `/wp-content/` (0.6) daje 100%, a samo ciasteczko `wordpress_*` daje 60%. UI pokazuje
pewność i dowody, czyli konkretny nagłówek, ciasteczko, fragment HTML albo ścieżkę.

## Klasa (priorytet analityczny 0–100%) i reguły klasy

Klasa to suma wag dopasowanych reguł, obcięta do 100%. Reguły są w tabeli `scoring_rules` i można je edytować w UI
(zakładka „Reguły klasy”):

| Rodzaj | Jak wpływa na klasę | Skąd się bierze |
|---|---|---|
| sygnatura | waga × pewność wykrycia (po połowie dla każdej detekcji + połowa najwyższej) | każda sygnatura (domyślnie jej pole `interest`) |
| reguła ogólna | pełna waga, gdy warunek spełniony | 10 reguł: wygasły / wygasający / self-signed certyfikat, stary TLS, logowanie bez TLS, wersja w Server, X-Powered-By, ciasteczko bez HttpOnly, niestandardowy port HTTP, ujawniona wersja usługi |
| port | pełna waga, gdy port jest otwarty | dopisywane **automatycznie** przy wykryciu nowego portu (waga 0, znacznik „do oceny”) albo ręcznie |

Zmiana wagi przelicza klasę wszystkich zapisanych obserwacji (bez ruchu sieciowego). Obserwacja przechowuje listę
dopasowanych reguł, więc UI pokazuje pokrycie „X z N reguł” (N = aktywne reguły z wagą > 0). Nowy port z wagą 0 nie
zmienia klasy, dopóki analityk go nie oceni. Dzięki temu klasy nie „pływają” przy rozbudowie katalogu reguł.

Opcja konfiguracji „dopisuj wykryte porty do listy” (domyślnie wyłączona) rozszerza listę portów skanu wyłącznie
o porty mieszczące się w liście „Porty zatwierdzone” ustawianej przez administratora.

## RBAC

Uprawnienia są atomowe (`targets.create`, `results.update`, `scans.run`, …). Role to zbiory uprawnień zapisane
w bazie. Wbudowane role (chronione przed zmianą):

| Rola | Zakres |
|---|---|
| Administrator | wszystko, w tym użytkownicy, role, ustawienia, audyt |
| Operator | dodawanie, usuwanie i modyfikacja celów, konfiguracji, skanów, wyników i sygnatur; import/eksport |
| Analityk | odczyt + modyfikacja istniejących danych (adnotacje, edycja wyników), eksport (bez wysyłki do DefectDojo) |
| Obserwator | odczyt i eksport |

Uprawnienia są sprawdzane w API (middleware `auth.Require`). UI tylko ukrywa niedostępne akcje. Sesja: JWT (HS256,
12 h) w ciasteczku HttpOnly + SameSite=Strict, limit nieudanych logowań, audyt każdej zmiany.

## Szyfrowanie w spoczynku

- Klucz główny (32 B) z `ASI_MASTER_KEY` albo z pliku/docker secret; nigdy nie trafia do bazy.
- Z klucza głównego HKDF wyprowadza osobne klucze: szyfrowanie pól (AES-256-GCM, losowy nonce) oraz HMAC (wyszukiwanie po polach zaszyfrowanych).
- Szyfrowane są: dane obserwacji (banery, nagłówki, ciasteczka z wartościami, tytuły, fragmenty HTML, certyfikaty,
  ścieżki), notatki (cele, skany, adnotacje), ustawienia (token DefectDojo).
- Jawne są wyłącznie pola potrzebne do indeksowania i diffu: IP, port, protokół, nazwa usługi/produktu/wersji,
  skrócona lista technologii, flagi, ocena.
- Hasła użytkowników: argon2id (sól 16 B, 64 MiB, 2 iteracje).
- Wdrożenie produkcyjne: dodatkowo szyfrowanie wolumenu (LUKS) lub przejście na PostgreSQL z TDE; rotacja klucza = odszyfrowanie i ponowne zaszyfrowanie pól nowym kluczem.

## Import sygnatur

`sig.Convert` rozpoznaje format pliku i konwertuje go do sygnatur MoNet: format natywny (YAML/JSON), szablony nuclei
(tylko zapytania GET bez payloadów; matchery word/regex/status/favicon), Wappalyzer (`technologies.json`: nagłówki,
ciasteczka, HTML, meta, skrypty, z wyciąganiem wersji) i CSV. Każda sygnatura jest kompilowana. Elementy niebezpieczne
lub nieobsługiwane (POST, payloady, wzorce spoza RE2, detekcja wyłącznie po JS) trafiają do ostrzeżeń w podglądzie.

## Integracja z DefectDojo: reimport i weryfikacja

Eksport obserwacji jako findingi `Info` (Generic Findings Import) przez `import-scan` (nowy test) albo `reimport-scan`
(stały test: DefectDojo dopisuje nowe, zamyka zniknięte, przywraca powracające). Deterministyczny opis (bez zmiennych
nagłówków, posortowane flagi) jest warunkiem poprawnej deduplikacji. Każda wysyłka trafia do tabeli `dojo_pushes`
z licznikami zmian po stronie DefectDojo. Skrypt `scripts/dojo_series.py` przeprowadza serie skanów na zmieniających
się pulach adresów i po każdym porównuje identyfikatory aktywnych findingów w DefectDojo z obserwacjami wysłanymi przez MoNet.

## Skalowanie

- 16 384 adresy (lab, ~1400 żywych hostów, ~2100 usług): pełny skan ok. 12–13 min na 6 workerach przy 3000 pakietów/s
  (pomiary w `docs/POMIARY.md`).
- Planer, ekspansja celów i diff działają na zbiorach w pamięci. Twardy limit to 1 048 576 adresów na skan.
- Wąskie gardło w gęstych sieciach to `-sV` i sondy HTTP, a nie discovery. Regulują je workery, `--max-rate`
  i limit HTTP/s.
