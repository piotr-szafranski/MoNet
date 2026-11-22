# MoNet: instrukcja uruchomienia i testu w środowisku AGH

Instrukcja dla zespołu testującego: jak uruchomić MoNet, podłączyć go do laboratorium AGH i przejść wszystkie
punkty testu (dwa przebiegi skanu, porównanie, edycja znalezisk, import i eksport, role, DefectDojo).
Polecenia wpisuje się w terminalu na maszynie z Dockerem. Przy każdym poleceniu jest krótkie wyjaśnienie.

Repozytorium: **https://github.com/piotr-szafranski/MoNet**

> **Zasada bezpieczeństwa:** MoNet skanuje wyłącznie adresy z listy celów i tylko w sieciach dozwolonych przez
> administratora (Administracja → Polityka Skanera). Domyślnie dozwolone są wyłącznie sieci prywatne.

---

## 1. Wymagania

| Element | Wymaganie |
|---|---|
| System | Linux z Dockerem i Docker Compose v2 (`docker compose`) |
| Zasoby | ok. 1 GB RAM, 1 GB miejsca na dysku |
| Port | 8080 (interfejs WWW MoNet) |
| Sieć | dostęp do sieci, w której działa laboratorium AGH (patrz krok 3) |

Nmap jest wbudowany w obraz MoNet, nie trzeba go instalować osobno.

---

## 2. Pobranie i uruchomienie

```bash
git clone https://github.com/piotr-szafranski/MoNet.git
cd MoNet
```
*Pobiera kod MoNet i przechodzi do katalogu projektu.*

```bash
printf "ASI_MASTER_KEY=$(openssl rand -base64 32)\nASI_ADMIN_PASSWORD=ZmienToHaslo2026\nASI_DEMO_USERS=1\n" > .env
```
Tworzy plik `.env` z ustawieniami:

- `ASI_MASTER_KEY`: losowy klucz szyfrowania danych w spoczynku (AES-256-GCM);
- `ASI_ADMIN_PASSWORD`: hasło konta `admin`, co najmniej 10 znaków (wpisz własne);
- `ASI_DEMO_USERS=1`: dodatkowo tworzy konta demo dla czterech ról (krok 12). Bez tej linii powstaje tylko `admin`.

```bash
docker compose up -d --build
```
*Buduje obraz (frontend, backend w Go i nmap) i uruchamia kontener `asi-app` w tle. Pierwsze uruchomienie trwa
kilka minut.*

```bash
docker logs --tail 20 asi-app
```
*Pokazuje ostatnie linie dziennika. Powinno być widać „MoNet nasłuchuje na :8080”.*

Interfejs: **http://localhost:8080** (albo `http://<adres maszyny>:8080`). Logowanie: `admin` i hasło z pliku `.env`.
Przy pierwszym logowaniu otwiera się krótki samouczek (8 kroków), który można pominąć.

---

## 3. Podłączenie MoNet do laboratorium AGH

Wybierz wariant zależnie od tego, jak uruchomione jest laboratorium.

**Wariant A: kontenery AGH działają w Dockerze na tej samej maszynie (zalecany).**

```bash
docker network ls
```
*Wyświetla sieci Dockera. Szukamy sieci laboratorium AGH (np. `agh_default` albo nazwy z ich pliku compose).*

```bash
docker network inspect <sieć_AGH> -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
```
*Podaje zakres adresów sieci laboratorium, np. `172.20.0.0/24`. Zapisz go, to będzie cel skanu.*

```bash
docker network connect <sieć_AGH> asi-app
```
*Dołącza kontener MoNet do sieci laboratorium. MoNet widzi wtedy kontenery AGH bezpośrednio, na ich wewnętrznych portach.*

**Wariant B: laboratorium jest na innej maszynie albo usługi są wystawione na portach hosta.**
W pliku `docker-compose.yml` odkomentuj linię `network_mode: host` i usuń linię `ports`, potem:

```bash
docker compose up -d
```
*MoNet korzysta wtedy bezpośrednio z sieci maszyny (surowe pakiety nmapa, ARP). Interfejs nadal na porcie 8080.*

**Sprawdzenie łączności (tylko wykrywanie hostów, bez skanu portów):**

```bash
docker exec asi-app nmap -sn -n <zakres_AGH>
```
*Powinny pojawić się linie `Host is up` dla kontenerów AGH.*

---

## 4. Polityka skanera (Administracja → Polityka Skanera)

Domyślnie MoNet pozwala skanować tylko sieci prywatne (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
`100.64.0.0/10`) z limitami 5000 pakietów/s, 100 zapytań HTTP/s i 8 równoległych podgrup.

- **Jeśli cel to `127.0.0.1` (usługi wystawione na localhost) albo adres publiczny,** dopisz go w polu
  „Dozwolone sieci” (np. `127.0.0.0/8`) i zapisz. Inaczej MoNet odrzuci cel już przy dodawaniu.
- **Jeśli AGH podało limity ruchu,** wpisz je tu jako maksymalne tempo. Żadna konfiguracja skanu ich nie przekroczy
  (przy zapisie pojawi się komunikat o obcięciu), a skan sprawdza politykę także przy każdym wznowieniu.
- Opcja „Nie sprawdzaj ścieżek ogólnych” wyłącza zapytania o `/admin`, `/.env`, `/.git/HEAD`, `/server-status`
  na każdej usłudze HTTP (zostają tylko ścieżki potwierdzające technologię).

---

## 5. Cele skanowania (zakładka Cele)

1. **Wprowadzenie ręczne:** wpisz zakres z kroku 3 (adresy, CIDR, zakresy `a-b` albo domeny), dodaj tag `agh`
   i kliknij **Dodaj cele**.
2. **Import z pliku CSV / JSON:** ten sam efekt dla listy celów od AGH (format opisany na ekranie).
3. Jeśli lista zawiera cele spoza testu, wyłącz je przełącznikiem „Aktywny”.

*Błędne adresy (np. `10.0.0.300`) i odwrócone zakresy są odrzucane z komunikatem; nakładające się cele dają ostrzeżenie.*

---

## 6. Konfiguracja skanu (przycisk „+” albo Skany → Konfiguracje → Nowa konfiguracja)

Kreator prowadzi przez pięć kroków:

| Krok | Co ustawić |
|---|---|
| Podstawy | nazwa (np. `AGH test`), tagi celów: `agh` |
| Porty | lista dozwolonych portów od AGH, np. `21,22,80,443,8080-8090` (prefiksy `T:`/`U:` dla TCP/UDP) |
| Intensywność | limit pakietów/s, równoległość, zapytania HTTP/s, timeouty; każde pole ma objaśnienie (i) |
| Harmonogram i doskaner | tryb Ręczny albo Automatyczny z oknem czasowym (np. 22:00–06:00) i doskanerem dziennym |
| DefectDojo i zapis | opcjonalny automatyczny eksport po skanie; szacowany czas skanu przy przycisku Zapisz |

Zalecane: **Reguły klasy → Porty zatwierdzone** – wklej tę samą listę portów. MoNet nie wyjdzie wtedy poza nią,
nawet przy automatycznym dopisywaniu portów.

---

## 7. Sygnatury od AGH (zakładka Sygnatury)

1. **Importuj z pliku** i wybierz plik od AGH. Format jest rozpoznawany automatycznie: MoNet YAML/JSON, szablony
   nuclei, Wappalyzer, CSV.
2. Sprawdź podgląd (liczba sygnatur, konflikty, ostrzeżenia) i zatwierdź.
3. Przy sygnaturze: **Testuj na zebranych wynikach** – sprawdza ją bez wysyłania ruchu do sieci.

Własną sygnaturę najszybciej utworzyć z nierozpoznanej usługi: **Usługi → szczegóły usługi → Naucz system**.
*Sygnatury tylko odczytują odpowiedzi; ścieżki przekazujące dane logowania są odrzucane.*

---

## 8. Skan nr 1 i skan nr 2 (wykrywanie zmian)

1. **Skany → Konfiguracje → Uruchom.** Postęp, tempo i szacowany czas widać na dashboardzie i w historii skanów.
   Wyniki trafiają do bazy po każdej podgrupie adresów, więc **Usługi** i **Hosty** wypełniają się w trakcie.
2. Po zmianach w środowisku AGH uruchom skan ponownie.
3. **Zmiany:** wybierz regułę, skan A i skan B. Widać nowe, znikające, zmienione (pole po polu) i powracające
   usługi oraz hosty. Oś czasu pokazuje różnice dla kolejnych skanów reguły. Różnice można pobrać jako CSV/JSON.
4. **Hosty** i **Usługi** mają trzy widoki z licznikami:

| Widok | Znaczenie |
|---|---|
| Aktywne | host widziany w skanie w ciągu ostatnich 24 godzin |
| Niestabilne | widziany w ciągu 24 godzin, ale nie w skanach nocnych (22:00–06:00), np. stacja wyłączana na noc |
| Niedostępne | niewidziany dłużej niż 48 godzin albo nigdy; doskaner sprawdza takie adresy w dzień po kolei |

*Skan, który nie zmieści się w oknie czasowym, zatrzymuje się i wznawia od miejsca przerwania w kolejnym oknie
(także po restarcie kontenera).*

---

## 9. Edycja znalezisk

1. **Usługi → kliknij usługę → Edytuj wynik:** popraw produkt, wersję, technologie, klasę albo notatkę i zapisz.
   Poprawka obowiązuje także w **kolejnych skanach**. Przestaje obowiązywać sama, gdy skaner zobaczy inną wersję
   (prawdziwa zmiana pozostaje widoczna w porównaniu).
2. **Cofnij poprawkę** przywraca wynik skanera dokładnie w takiej postaci, w jakiej był.
3. **Adnotacje → fałszywy alarm:** usługa zostaje w bazie i historii, ale nie jest liczona na dashboardzie
   i nie trafia do DefectDojo.

---

## 10. Import i eksport danych (zakładka Import / eksport)

- **Import wyników skanu:** XML nmapa, JSON albo CSV (np. wyniki referencyjne AGH). Plik trafia jako osobny skan,
  który można porównać z własnym skanem w zakładce Zmiany.
- **Eksport:** cele, inwentarz usług, wyniki skanu i różnice między skanami jako **CSV** albo **JSON**.
- **Dziennik logów** (Administracja): pobieranie JSON/CSV/TXT dla dnia albo całości.

---

## 11. DefectDojo

1. **Import / eksport → Ustawienia DefectDojo:** adres instancji od AGH, token API, produkt i engagement → **Zapisz**,
   potem **Test połączenia**. Token jest przechowywany w bazie w postaci zaszyfrowanej.
2. **Eksport do DefectDojo:** wybierz skan i minimalną klasę, zaznacz reimport do stałego testu → **Wyślij**.
   Obserwacje trafiają jako findingi informacyjne z dowodami.
3. Po kolejnym skanie **Historia Importowania do DefectDojo** pokazuje findingi nowe, zamknięte, przywrócone
   i bez zmian. Nieudaną wysyłkę można ponowić przyciskiem **Ponów**.
4. Opcjonalnie w konfiguracji skanu: automatyczny reimport po każdym skanie.

---

## 12. Role (RBAC)

Konta demo (gdy w `.env` jest `ASI_DEMO_USERS=1`): `operator / operator123!`, `analityk / analityk123!`,
`obserwator / obserwator123!`. Można też utworzyć konta w **Administracja → Użytkownicy**.

| Rola | Uprawnienia |
|---|---|
| Obserwator | tylko odczyt i eksport |
| Analityk | odczyt i modyfikacja istniejących danych (edycja wyników, adnotacje, klasyfikacja technologii), eksport; bez dodawania, usuwania i wysyłki do DefectDojo |
| Operator | dodawanie, usuwanie i modyfikacja (cele, konfiguracje, sygnatury, skany), wysyłka do DefectDojo; bez Administracji |
| Administrator | wszystko, w tym użytkownicy, role, polityka skanera, ustawienia DefectDojo i dziennik logów |

*Uprawnienia są sprawdzane po stronie serwera (API), nie tylko ukrywane w interfejsie. Każdy użytkownik zmienia
własne hasło w menu konta (awatar → Zmień hasło).*

---

## 13. Bezpieczeństwo działania skanera

- Skanowane są tylko adresy z listy celów, w sieciach dozwolonych przez politykę; wykluczenia są respektowane.
- Sondy HTTP to wyłącznie `GET` (bez logowania i bez payloadów); przekierowania poza zakres są tylko zapisywane.
- Limity: pakiety/s nmapa, zapytania HTTP/s, timeout hosta, ponowienia, równoległość.
- Skaner przedstawia się nagłówkiem `User-Agent: MoNet-DiscoveryScanner/1.0`.
- Wykrywanie soft-404: serwer odpowiadający „200” na każdą ścieżkę nie generuje fałszywych trafień.

---

## 14. Sprzątanie po teście

```bash
docker network disconnect <sieć_AGH> asi-app
```
*Odłącza MoNet od sieci laboratorium (wariant A).*

```bash
docker compose down
```
*Zatrzymuje MoNet. Dane zostają w wolumenie `asi-data`; `docker compose down -v` usuwa je razem z wolumenem.*

---

## Rozwiązywanie problemów

| Objaw | Rozwiązanie |
|---|---|
| `docker compose up` kończy się błędem „ustaw ASI_ADMIN_PASSWORD” | brak pliku `.env` albo wpisu; wróć do kroku 2 |
| Cel odrzucony: „poza sieciami dozwolonymi przez administratora” | dopisz sieć w Administracja → Polityka Skanera (krok 4) |
| MoNet nie widzi hostów AGH | sprawdź `docker network connect` (wariant A) albo `network_mode: host` (wariant B) i test z kroku 3 |
| Skan ma stan „wstrzymany” | skończyło się okno czasowe; skan wznowi się w kolejnym oknie albo po kliknięciu Uruchom |
| Logowanie zablokowane | po 10 nieudanych próbach dany login jest blokowany na 5 minut |
| Stary wygląd strony po aktualizacji | odśwież z pominięciem pamięci podręcznej: Ctrl+Shift+R |
| Dziennik aplikacji | `docker logs --tail 50 asi-app` |

Dokumentacja szczegółowa: `README.md`, `docs/ARCHITEKTURA.md`, `docs/FORMATY.md`, `docs/DEFECTDOJO.md`,
wyniki testów: `docs/POMIARY.md`, `docs/TEST_LAB_AGH.md`.
