# Pomiary i testy (lab MoNet, 21.11.2026)

Środowisko: serwer z Dockerem, lab w odizolowanej sieci `10.66.0.0/18` (16 384 adresy). Symulator `labsim` wystawia
~1500 hostów w 30 profilach z indywidualnymi wersjami i tytułami (część hostów niestabilnych, zależnych od pory dnia
i zmieniających się między fazami). Do tego prawdziwe kontenery nginx, httpd i Valkey. Konfiguracja skanu: 16 portów TCP,
limit 3000 pakietów/s, 6 workerów, 60 zapytań HTTP/s, cel podgrupy 30 s.

## 1. Czas i wydajność skanu (16 382 adresy)

| Skan | Wersja silnika | Czas | Tempo | Hosty | Usługi | Podgrup | Rozmiar podgrupy (min / mediana / maks) | Mediana czasu podgrupy |
|---|---|---|---|---|---|---|---|---|
| #1 | pierwsza (wszystkie ścieżki sygnatur na każdej usłudze HTTP) | 12 min 22 s | 22,1 IP/s | 1453 | 2155 | 112 | 62 / 128 / 704 | 35 s |
| #2 | dwuetapowe sondy ścieżek | **9 min 01 s** | 30,2 IP/s | 1452 | 2154 | 83 | 62 / 128 / 704 | 36 s |
| #7 | zapis inwentarza na bieżąco | **8 min 39 s** | 31,6 IP/s | 1461 | 2160 | 84 | 128 / 128 / 704 | 37 s |

- Planer dopasowuje rozmiar podgrupy do zmierzonego tempa: w pustych segmentach sieci podgrupy rosną do 704
  adresów, w gęstych spadają do 64–128. Mediana czasu podgrupy (35–37 s) jest blisko zadanego celu (30 s).
- Dwuetapowe sondy (ścieżki potwierdzające tylko przy częściowym dopasowaniu strony głównej) skróciły skan o 27%.
- Wąskim gardłem w gęstej sieci jest wykrywanie wersji (`-sV`) i sondy HTTP, a nie discovery.

## 2. Trafność (porównanie z prawdziwym stanem symulatora, `scripts/accuracy.py`)

| Skan | Hosty (precyzja / czułość) | Porty (precyzja / czułość) | Technologie (wykryte / oczekiwane) |
|---|---|---|---|
| #1 | 100% / 100% (1394) | 100% / 100% (2053) | 2588 / 2729 (94,8%): poprawiono usługi na portach 3000 i 9200 oraz staging w certyfikacie |
| #2 | 100% / 100% (1394) | 100% / 100% (2053) | **2729 / 2729 (100%)** |
| #7 | 100% / 100% (1394) | 100% / 100% (2053) | **2729 / 2729 (100%)** |
| #8 (zróżnicowane hosty) | 100% / 100% (1394) | 100% / 100% (2412) | **2943 / 2943 (100%)** |

Hosty o zachowaniu zmiennym (106: niestabilne, „dzienne”, zmieniające się) są oceniane osobno, bo ich stan zależy od
chwili skanu. Pokazuje je porównanie skanów i stany hostów.

## 3. Okno czasowe i wznawianie (skan #3)

| Zdarzenie | Czas |
|---|---|
| harmonogram uruchamia skan w oknie 13:32–13:34 | 13:32:00 |
| koniec okna: skan zatrzymany na 4 032 / 16 382 adresach | 13:34:00 |
| kolejne okno 13:35: wznowienie od nieukończonych bloków (193 z 256) | 13:35:00 |
| skan zakończony, wszystkie 16 382 adresy, 2 okna | 13:54:24 |

## 4. Wyniki na bieżąco

Po 40 s skanu #5 baza urządzeń zawierała już 94 hosty z tego przebiegu (inwentarz aktualizowany po każdej podgrupie).
Cel podany jako pojedynczy adres bez odpowiedzi (`10.66.7.250`) został zapisany jako „nieosiągalny” od razu
w swojej podgrupie.

## 5. Doskanowanie w ciągu dnia

Doskaner sprawdzał nieosiągnięte końcówki pojedynczo (1 adres, przerwa 10 s, czyli ~13 s na adres). Po zmianie fazy
symulatora host `10.66.36.53` odpowiedział przy kolejnej próbie i został od razu zapisany w bazie razem z usługą
HTTP. Historia `10101` dała stan „niestabilny”.

## 6. Porównanie skanów

Diff #1 → #2: 6 nowych i 7 znikających hostów (hosty niestabilne), 24 nowe i 25 znikających usług (porty zależne od
fazy), 22 zmiany wersji (profil „changing”). Porównanie obejmuje wyłącznie porty i adresy wspólne dla obu skanów.

## 7. Role (RBAC, `scripts/rbac_test.py`)

13 akcji × 4 role (Obserwator, Analityk, Operator, Administrator): **wszystkie uprawnienia zgodne z rolami**.
Test wyłapał i pomógł naprawić jedną niezgodność: Operator miał dostęp do dziennika audytu.

## 8. DefectDojo

- Seria ręczna z interpretacją: [DEFECTDOJO_TESTY.md](DEFECTDOJO_TESTY.md) (deduplikacja, zamykanie, przywracanie).
- Seria automatyczna na zmieniających się pulach adresów z weryfikacją zgodności findingów: [DEFECTDOJO_SERIA.md](DEFECTDOJO_SERIA.md).

## 9. Jakość kodu i uruchomienie

- Testy jednostkowe (`go test ./internal/...`): porty, cele (CIDR, zakresy, CSV/JSON), szyfrowanie (AES-GCM, argon2id),
  okna czasowe (także przez północ), stany hostów, planer podgrup, sygnatury, import sygnatur (nuclei, Wappalyzer,
  CSV, MoNet), import wyników (XML nmapa, JSON, CSV).
- `scripts/api_null_check.py`: 30 endpointów bez nieoczekiwanych wartości `null` (test regresji po błędzie „czarnego ekranu”).
- Obraz produkcyjny zbudowany od zera i uruchomiony z czystą bazą (`deploy/prodtest.yml`).

## 10. Pomiary po poprawkach z oceny krytycznej (22.11.2026)

**Pełna sieć /18 po poprawkach (skan #71, reguła „Lab pełny”, 22.11 04:56–05:07):**

| Parametr | Wartość |
|---|---|
| Adresy | 16 381 |
| Żywe hosty | 1 489 |
| Otwarte usługi | 2 547 |
| Czas | **11 min 09 s**, jedno okno |
| Porty | 21-23,80,443,554,3000,3306,3389,6379,8000,8080-8081,8443,9100,9200 |

Niezależna kontrola krytyka na 10.66.8.0/24 (skany #69, #70) względem `/truth` symulatora: 28/28 hostów, 43/43 portów.

**Soft-404 (fałszywe trafienia ścieżek):**

| Usługa | Przed (skan #65) | Po (skan #71) |
|---|---|---|
| 10.66.8.123:80, GoAhead, „Web Viewer” | Panel /admin, Kamera IP 70%, Formularz logowania | Kamera IP 30% (słaba przesłanka), Formularz logowania |
| 10.66.8.62:3000, Grafana | Grafana, Panel /admin | Grafana, Formularz logowania |

Serwer GoAhead w labie odpowiada 200 na każdą ścieżkę. Zapytanie kontrolne o nieistniejący adres (jedno na usługę HTTP
z ścieżkami do sprawdzenia) pozwala odrzucić trafienia identyczne z tą odpowiedzią. Prawdziwa treść, np. `/.env` z
inną zawartością, zostaje (test `httpprobe/soft404_test.go`).

**Testy jednostkowe (pokrycie):** auth 82%, diff 79%, ports 87%, targets 72%, sig 69%, export 67%, secure 48%,
dojo 35%, httpprobe 25%, scan 15%. Nowe testy: trwałe poprawki analityka (także unieważnianie poprawki przy zmianie
wersji), polityka skanera, RBAC i unieważnianie tokenów, porównanie skanów, soft-404, ochrona CSV, ponowienia DefectDojo.
