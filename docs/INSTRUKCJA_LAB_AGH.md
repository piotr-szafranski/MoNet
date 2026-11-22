# Instrukcja: uruchomienie testów na środowisku od AGH

Instrukcja krok po kroku: jak uruchomić materiały od AGH (kontenery z testowym środowiskiem), podłączyć do nich MoNet
i przejść cały test. Przy każdym poleceniu jest wyjaśnienie, **co ono robi**. Polecenia wpisuje się w terminalu
na serwerze (po zalogowaniu przez SSH).

> **Zasada nr 1:** skanujemy wyłącznie środowisko od AGH (albo nasz lab). Nigdy nie wpisujemy w MoNet adresów spoza
> tego, co AGH wskaże jako cel testu.

---

## 0. Co dostaniemy od AGH i gdzie to położyć

AGH zapowiedziało, że udostępni (na Discordzie albo przy stanowisku):

| Materiał | Co z nim zrobimy |
|---|---|
| konfiguracja kontenerów (zwykle plik `docker-compose.yml`) | uruchomimy środowisko testowe (krok 3) |
| zasady bezpiecznego skanowania, limity ruchu | ustawimy limity w konfiguracji skanu (krok 9) |
| lista dozwolonych portów | wpiszemy w polu „Porty” (krok 8) |
| przykładowe wyniki referencyjne | zaimportujemy i porównamy z naszym skanem (krok 12) |
| przykładowe sygnatury | zaimportujemy w zakładce Sygnatury (krok 10) |
| przykładowy format importu/eksportu | sprawdzimy import i eksport (krok 14) |
| opcjonalnie: testowa instancja DefectDojo | podłączymy w ustawieniach (krok 13) |

Wszystko zapisujemy w jednym katalogu:

```bash
mkdir -p /opt/hacknation/projekt/piotr/agh
```
*Tworzy katalog `agh` na materiały od AGH. Jeśli już istnieje, nic się nie dzieje.*

Pliki z własnego komputera wrzucamy na serwer (polecenie wpisujemy **na swoim Macu**, nie na serwerze):

```bash
scp -r ~/Downloads/materialy-agh/* pszafranski@10.1.3.155:/opt/hacknation/projekt/piotr/agh/
```
*Kopiuje pliki z folderu `materialy-agh` na Macu do katalogu `agh` na serwerze. Jeśli jesteśmy poza siecią
lokalną, zamiast `10.1.3.155` wpisujemy `100.84.180.79` (Tailscale).*

---

## 1. Zaloguj się na serwer i przejdź do projektu

```bash
ssh pszafranski@10.1.3.155
```
*Łączy z serwerem. Od tej chwili polecenia wykonują się na serwerze.*

```bash
cd /opt/hacknation/projekt/piotr/asi
```
*Przechodzi do katalogu z kodem MoNet. Kolejne polecenia zakładają, że tu jesteśmy.*

```bash
docker ps --format '{{.Names}}\t{{.Status}}' | grep asi-
```
*Pokazuje nasze działające kontenery. Powinniśmy zobaczyć `asi-app` (aplikacja) i ewentualnie `asi-lab-*`
(nasz własny lab) oraz `asi-dojo-*` (nasz testowy DefectDojo).*

---

## 2. Obejrzyj konfigurację od AGH, zanim ją uruchomisz

```bash
ls -la ../agh/
```
*Pokazuje, jakie pliki przyszły od AGH.*

```bash
cat ../agh/docker-compose.yml
```
*Wyświetla plik z konfiguracją kontenerów. Szukamy w nim trzech rzeczy:*

- *`networks:` – jak nazywa się sieć i jaki ma zakres adresów (np. `172.30.0.0/24`), bo to będzie nasz cel skanu,*
- *`ports:` – czy coś jest wystawiane na zewnątrz serwera (np. `"80:80"`). Jeśli port jest już zajęty na serwerze, uruchomienie się nie uda (patrz „Problemy”, punkt A),*
- *`container_name:` – nazwy kontenerów (przydadzą się do sprawdzania).*

> Jeśli plik jest inny niż `docker-compose.yml` (np. `compose.yaml` albo kilka plików), podstawiamy jego nazwę
> w poleceniach poniżej.

---

## 3. Uruchom środowisko testowe AGH

```bash
docker-compose -p asi-agh -f ../agh/docker-compose.yml up -d
```
*Uruchamia kontenery AGH w tle (`-d`). `-p asi-agh` nadaje projektowi nazwę z prefiksem `asi-`, więc łatwo
odróżnić nasze zasoby od zasobów innych osób na serwerze. Przy pierwszym uruchomieniu Docker pobiera obrazy,
co może potrwać kilka minut.*

```bash
docker-compose -p asi-agh -f ../agh/docker-compose.yml ps
```
*Pokazuje stan kontenerów AGH. Wszystkie powinny mieć stan `Up` (działa).*

---

## 4. Sprawdź, w jakiej sieci działają kontenery AGH

```bash
docker network ls | grep asi-agh
```
*Wyświetla sieci utworzone przez projekt AGH, np. `asi-agh_default` albo nazwę z ich pliku.*

```bash
docker network inspect asi-agh_default -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
```
*Podaje zakres adresów tej sieci, np. `172.30.0.0/24`. **Zapisz go.** To będzie cel skanu w kroku 7.
(Zamiast `asi-agh_default` wpisz nazwę sieci z poprzedniego polecenia.)*

```bash
docker network inspect asi-agh_default -f '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}'
```
*Wypisuje kontenery AGH z ich adresami IP. Przyda się do sprawdzenia, czy MoNet znalazło wszystkie hosty.*

---

## 5. Podłącz MoNet do sieci AGH

MoNet działa w swoim kontenerze `asi-app`. Żeby mogło skanować kontenery AGH, musi być w tej samej sieci.

**Sposób szybki (do końca testu):**

```bash
docker network connect asi-agh_default asi-app
```
*Dołącza kontener `asi-app` do sieci AGH. Aplikacja działa dalej bez restartu i od razu widzi hosty AGH.*

```bash
docker exec asi-app ip -4 addr | grep inet
```
*Pokazuje adresy kontenera MoNet. Jeden z nich powinien należeć do zakresu z kroku 4. To znaczy, że połączenie działa.*

**Sposób trwały (po restarcie też działa):** w pliku `docker-compose.lab.yml` w sekcji `networks:` dopisujemy sieć AGH
tak samo jak `asi-lab`:

```yaml
    networks: [default, lab, agh]
networks:
  lab: { external: true, name: asi-lab }
  agh: { external: true, name: asi-agh_default }
```
*Mówi Dockerowi, że MoNet ma być zawsze podłączone także do sieci AGH.*

```bash
docker-compose -p asi -f docker-compose.lab.yml up -d
```
*Przeładowuje kontener MoNet z nową konfiguracją sieci. **Uwaga:** przerywa trwający skan (potem klikamy „Wznów”).*

**Wariant: AGH daje środowisko na osobnej maszynie lub w sieci stanowiska (nie w Dockerze na naszym serwerze).**
Wtedy MoNet musi widzieć tę sieć bezpośrednio. Uruchamiamy wersję z siecią hosta:

```bash
docker-compose -p asi -f docker-compose.yml up -d --build
```
*W pliku `docker-compose.yml` odkomentowujemy wcześniej linię `network_mode: host` i usuwamy sekcję `ports`. MoNet
korzysta wtedy bezpośrednio z sieci serwera. Interfejs będzie pod adresem `http://10.1.3.155:8080`.*

---

## 6. Sprawdź łączność (krótki, pojedynczy test)

```bash
docker exec asi-app nmap -sn -n 172.30.0.0/24
```
*Wykonuje tylko wykrywanie hostów (bez skanowania portów) w sieci AGH. W wyniku powinny pojawić się linie
`Host is up` dla kontenerów AGH. Zamiast `172.30.0.0/24` wpisz zakres z kroku 4.*

Jeśli hostów nie ma, przejdź do „Problemy”, punkt B.

---

## 7. Zaloguj się do MoNet i dodaj cele

1. Otwórz w przeglądarce **http://10.1.3.155:8095** (albo `http://100.84.180.79:8095`).
   *Interfejs MoNet. Konta: `admin / admin123!`, `operator / operator123!`, `analityk / analityk123!`, `obserwator / obserwator123!`.*
2. Zaloguj się jako **admin**.
3. Wejdź w **Cele** i w polu „Wprowadzenie ręczne” wpisz zakres z kroku 4 (np. `172.30.0.0/24`). Dodaj tag `agh`.
   *Mówi MoNet, co wolno skanować. Skaner nigdy nie wyjdzie poza listę celów.*
4. Jeśli AGH dało listę hostów w pliku CSV/JSON: **Cele → Import z pliku**, tag `agh`.
   *Import działa tak samo jak wpis ręczny: ta sama walidacja i przetwarzanie.*
5. Jeśli w celach są jeszcze nasze adresy labu (`10.66.0.0/18`), **wyłącz je przełącznikiem „Aktywny”**.
   *Dzięki temu skan obejmie wyłącznie środowisko AGH.*

---

## 8. Utwórz konfigurację skanu z portami od AGH

1. **Skany → Nowa konfiguracja.**
2. **Nazwa:** np. `AGH test`.
3. **Tagi celów:** `agh`.
   *Skan obejmie tylko cele z tym tagiem.*
4. **Porty do skanowania:** wklej listę dozwolonych portów od AGH (np. `21,22,80,443,8080,8443`).
   *Pod polem pojawi się zielony znacznik z liczbą portów TCP/UDP. Czerwony oznacza błąd w zapisie (np. port spoza 1–65535).*
5. **Zapisz.**

Dodatkowo (zalecane): **Reguły klasy → Porty zatwierdzone** – wklej tę samą listę i zapisz.
*Zabezpieczenie: nawet jeśli ktoś włączy opcję automatycznego dopisywania portów, MoNet nie wyjdzie poza listę AGH.*

---

## 9. Ustaw limity zgodnie z zasadami bezpiecznego skanowania

W tej samej konfiguracji (przycisk **Edytuj**), sekcja „Intensywność i bezpieczeństwo”:

| Pole | Co oznacza | Bezpieczna wartość na start |
|---|---|---|
| Limit pakietów/s (łącznie) | maksymalny ruch nmapa w całym skanie | to, co podało AGH; jeśli nic: `500` |
| Workery (równolegle) | ile części sieci skanujemy naraz | `2–4` |
| Zapytań HTTP/s | tempo sprawdzania stron WWW | `10–20` |
| Timeout hosta (s) | ile maksymalnie czekamy na jeden host | `60` |
| Ponowienia sond | ile razy ponawiamy pytanie | `1` |

*Jeśli AGH poda np. „maks. 100 pakietów/s”, wpisujemy 100 w limicie pakietów i 5 w zapytaniach HTTP/s.*

Przycisk **„Szacuj czas”** pokazuje, ile mniej więcej potrwa skan przy tych ustawieniach.

---

## 10. Zaimportuj sygnatury od AGH

1. **Sygnatury → Importuj z pliku → Wybierz plik** (plik od AGH).
   *MoNet rozpozna format automatycznie: nasz YAML/JSON, szablony nuclei, Wappalyzer albo CSV.*
2. Sprawdź podgląd: liczbę sygnatur, konflikty i **ostrzeżenia**.
   *Ostrzeżenia mówią, co pominięto i dlaczego, np. zapytania POST nie są importowane ze względów bezpieczeństwa.*
3. Wybierz „pomiń” albo „nadpisz” przy konfliktach i kliknij **Importuj**.
4. Przy dowolnej sygnaturze: **Edytuj → Testuj na zebranych wynikach**.
   *Sprawdza sygnaturę na już zebranych odpowiedziach, bez wysyłania ruchu do sieci.*

> Jeśli format od AGH nie zostanie rozpoznany, poproś Claude o dopisanie konwertera (to kilkanaście minut pracy)
> albo przepisz sygnatury do CSV: `name,type,pattern`.

---

## 11. Skan nr 1 i skan nr 2 (wykrywanie zmian)

1. **Skany → przy konfiguracji „AGH test” → Uruchom.**
   *Rusza skan. Na dashboardzie i w szczegółach skanu widać pasek postępu z procentem, tempo i szacowany czas.*
2. Obserwuj **Dashboard** i **Usługi**: wyniki pojawiają się **na bieżąco**, po każdej przeskanowanej części sieci.
3. Po zakończeniu sprawdź wyniki: **Usługi** (lista usług, technologie, flagi), **Hosty**, **Technologie**.
4. AGH zrobi co najmniej dwa przebiegi skanu (zmieni coś w środowisku między nimi). Po ich zmianie: **Uruchom** ponownie.
5. **Zmiany:** wybierz skan A (pierwszy) i B (drugi).
   *Pokazuje nowe, znikające i zmienione usługi oraz hosty. Porównywane są tylko porty i adresy objęte oboma skanami.*
6. **Skany → zakładka „Niedostępne końcówki”:** hosty, które przestały odpowiadać.
   *Host, który odpowiada raz tak, raz nie, dostanie stan „niestabilny”.*

---

## 12. Porównaj z wynikami referencyjnymi AGH

1. **Import / eksport → Import wyników skanu → Wybierz plik** (wyniki referencyjne AGH). Nazwa: `Referencja AGH`.
   *MoNet rozpozna XML nmapa, JSON albo CSV. Plik trafia jako osobny „skan z importu”.*
2. **Zmiany:** A = `Referencja AGH`, B = nasz skan.
   *Różnice pokażą, co znaleźliśmy więcej, a czego brakuje względem referencji.*

---

## 13. DefectDojo (jeśli AGH da testową instancję)

1. **Import / eksport → Ustawienia DefectDojo:** adres instancji, **token API**, nazwa produktu i engagementu → **Zapisz**.
   *Token jest przechowywany w bazie w postaci zaszyfrowanej.*
2. **Test połączenia.**
   *Ma się pojawić „Połączenie działa”.*
3. **Eksport do DefectDojo:** wybierz skan, minimalną klasę (np. 20), zaznacz „aktualizuj stały test (reimport)” → **Wyślij**.
   *Wysyła wybrane obserwacje jako findingi informacyjne z dowodami.*
4. Po kolejnym skanie wyślij ponownie, a w **Historii wysyłek** zobaczysz, ile findingów jest bez zmian, nowych, zamkniętych i przywróconych.
5. Opcjonalnie w konfiguracji skanu włącz **„po zakończeniu skanu automatycznie aktualizuj test w DefectDojo”**.

Token z instancji demo: zaloguj się na https://demo.defectdojo.org/ → menu użytkownika → **API v2 Key**.

---

## 14. Import i eksport danych

- **Eksport:** w szczegółach skanu przyciski **CSV / JSON**, w Usługach eksport inwentarza, w Zmianach eksport różnic.
- **Import wyników w formacie AGH:** **Import / eksport → Import wyników skanu**. Jeśli ich format się nie wczyta,
  zapisz komunikat błędu i poproś Claude o dopasowanie.

---

## 15. Pokaż role (RBAC)

Wyloguj się i zaloguj kolejno na konta:

| Konto | Co powinno być widać |
|---|---|
| `obserwator / obserwator123!` | tylko odczyt i eksport; brak przycisków dodawania i edycji |
| `analityk / analityk123!` | odczyt + edycja (adnotacje, wyniki), bez dodawania i usuwania |
| `operator / operator123!` | dodawanie, usuwanie, modyfikacja; brak Administracji |
| `admin / admin123!` | wszystko, w tym użytkownicy, role i dziennik audytu |

*Uprawnienia są sprawdzane na serwerze, nie tylko ukrywane w interfejsie.*

---

## 16. Sprzątanie po teście

```bash
docker network disconnect asi-agh_default asi-app
```
*Odłącza MoNet od sieci AGH.*

```bash
docker-compose -p asi-agh -f ../agh/docker-compose.yml down
```
*Zatrzymuje i usuwa kontenery AGH razem z ich siecią. Nasze dane w MoNet zostają.*

---

## Problemy i rozwiązania

**A. „port is already allocated” przy uruchamianiu AGH (krok 3)**
Jakiś port z ich pliku jest zajęty na serwerze. W `../agh/docker-compose.yml` zmień lewą liczbę w `ports:`, np.
`"80:80"` na `"18080:80"`, i uruchom krok 3 ponownie. *Lewa liczba to port na serwerze, prawa w kontenerze. Do
skanowania przez MoNet wystawianie portów nie jest potrzebne, więc sekcję `ports:` można też usunąć.*

**B. MoNet nie widzi hostów AGH (krok 6)**
- sprawdź, czy wykonałeś krok 5 (`docker network connect …`),
- sprawdź, czy sieć z kroku 4 ma poprawną nazwę,
- jeśli sieć AGH ma ustawienie `internal: true`, to nie przeszkadza: MoNet jest wtedy w tej samej sieci.

**C. Skan stoi na „wstrzymany”**
Kliknij **Wznów** przy skanie. *Skan zatrzymuje się po końcu okna czasowego albo po restarcie aplikacji
i kontynuuje od miejsca przerwania.*

**D. Czarny ekran albo stary wygląd strony**
Odśwież z pominięciem pamięci podręcznej: **Ctrl+Shift+R** (Mac: **Cmd+Shift+R**).

**E. Nie mogę się zalogować (zbyt wiele prób)**
Po 10 nieudanych próbach MoNet blokuje logowanie z danego adresu na 5 minut. Odczekaj chwilę.

**F. Gdzie są logi aplikacji?**
```bash
docker logs --tail 50 asi-app
```
*Pokazuje ostatnie 50 linii z dziennika MoNet (start skanu, zatrzymanie, błędy).*
