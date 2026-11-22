# Testy na szablonach labu od mentorów AGH (udostępnione 21.11.2026)

Stacki AGH uruchamiane po jednym z kopii w `lab/agh/` (obrazy i konfiguracja usług bez zmian). Różnice:
- nazwa projektu `asi-agh-*`,
- brak portów na hoście,
- usługi publikowane przez AGH dostają adres w izolowanej sieci `asi-lab` (10.66.4.0/24),
- bazy danych bez portu u AGH zostają tylko w sieci wewnętrznej.

Porty wewnętrzne kontenerów odpowiadają portom publikowanym przez AGH (np. 8787 → 80).

## Stack 1: custom-network (quickstart AGH: znikająca i powracająca usługa)

| Adres | Usługa AGH (port u AGH) | Co wykrył MoNet | Klasa |
|---|---|---|---|
| 10.66.4.14:3000 | Gitea (3001) | Gitea, **odsłonięty kreator instalacji**, formularz logowania, logowanie bez TLS | 70% |
| 10.66.4.14:22 | Gitea SSH (2223) | OpenSSH 10.3 | 3% |
| 10.66.4.13:15672 | RabbitMQ panel (15673) | RabbitMQ Management (panel admina) | 28% |
| 10.66.4.13:5672 | RabbitMQ AMQP (5673) | Broker AMQP (RabbitMQ) | 10% |
| 10.66.4.12:5432 | PostgreSQL (15432) | PostgreSQL | 19% |
| 10.66.4.11:80 | httpbin (8888) | httpbin, Gunicorn | 14% |
| 10.66.4.15:80 | nginx „flask-app” (8787) | nginx 1.31.9, domyślna strona | 8% |

Wynik: 5/5 hostów, 7/7 usług, ok. 48 s na skan.

Scenariusz quickstartu (skany #50 → #51 → #52):
- **A → B** (usługa 8787 zatrzymana): zniknął 1 host i 1 usługa, reszta bez zmian. ✅
- **B → C** (usługa przywrócona): host i usługa oznaczone jako **„wróciła”**, bo były widziane wcześniej. ✅

Poprawki po teście:
- 5 nowych sygnatur: Gitea, odsłonięty kreator instalacji, RabbitMQ Management, broker AMQP, httpbin.
- Nowy rodzaj zmiany „wróciła” w porównaniu skanów i na dashboardzie.

## Stack 2: modern (WordPress, phpMyAdmin, Redis, Nginx Proxy Manager)

| Adres | Usługa AGH (port u AGH) | Co wykrył MoNet (skan #55) |
|---|---|---|
| 10.66.4.31:80 | WordPress (8080) | WordPress, **odsłonięty kreator instalacji**, Apache 2.4.71, PHP |
| 10.66.4.32:80 | phpMyAdmin (8081) | phpMyAdmin (panel admina), formularz logowania bez TLS |
| 10.66.4.33:6379 | Redis (6379) | Redis 7.4.12, baza danych |
| 10.66.4.34:81 | NPM panel (81) | OpenResty, tytuł „Nginx Proxy Manager”. **Brak nazwy produktu i flagi panelu** |
| 10.66.4.34:80 | NPM (80) | OpenResty, tytuł „Default Site”. **Brak oznaczenia jako strona domyślna** |
| 10.66.4.34:443 | NPM (443) | HTTPS, flaga „TLS bez certyfikatu (SNI)”. Serwer nie wystawia certyfikatu dla samego adresu IP |

Port 3000 (NPM) widać tylko u nas, bo w naszej płaskiej sieci widoczne są porty wewnętrzne. AGH go nie publikuje,
więc nie liczymy go w ocenie.

Poprawki ogólne po teście:
- **Technologia z banera:** każdy produkt rozpoznany przez nmapa albo z nagłówka `Server` trafia do technologii,
  także bez sygnatury (`source: nmap` / `nagłówek Server`).
- **Stan TLS:** port, który wymaga TLS, ale nie wystawia certyfikatu bez nazwy hosta, jest oznaczany jako `https`
  z flagą `tls-bez-certyfikatu` (reguła klasy), zamiast jako HTTP z błędem 400.

## Stack 4: vulnerable (WordPress 4.7, MySQL 5.7, Adminer, vsftpd, DVWA), 22.11.2026

Obrazy były już na serwerze (pobrane razem z labem), stack w izolowanej sieci `asi-lab`, bez portów na hoście.
Reguła „AGH vulnerable”, porty 21,22,80,443,3306,8080,8088-8090,21000-21010.

| Adres | Usługa AGH (port u AGH) | Skan #74 (przed) | Skan #75 (po nowych sygnaturach) | Klasa |
|---|---|---|---|---|
| 10.66.4.21:80 | WordPress 4.7 (8088) | WordPress bez wersji, odsłonięty kreator instalacji, Apache 2.4.10, PHP 5.6.30 | **WordPress 4.7.5**, kreator instalacji, Apache 2.4.10, PHP 5.6.30 | 55% |
| 10.66.4.22:8080 | Adminer (8089) | tylko PHP 8.4 i formularz logowania | **Adminer (panel bazy danych)**, logowanie bez TLS | 54% |
| 10.66.4.23:21 | vsftpd (21) | vsftpd 3.0.2, serwer FTP | bez zmian | 11% |
| 10.66.4.24:80 | DVWA (8090) | formularz logowania, środowisko testowe | **DVWA 1.10 (celowo podatna aplikacja)**, ciasteczko bez HttpOnly, staging | 90% |

MySQL nie jest publikowany przez AGH (tylko sieć wewnętrzna stacku), więc nie liczymy go w ocenie.

Wynik: 4/4 hosty, 4/4 usługi, ok. 21 s na skan. Po teście dopisane 2 sygnatury (Adminer, DVWA) i wersja WordPressa
ze strony instalacji (`install.min.css?ver=`). Najwyższą klasę dostaje DVWA (90%), co odpowiada intencji stacku.

## Ocena pokrycia (lista kontrolna wg briefu i README AGH)

| Stack | Przed poprawkami | Po poprawkach |
|---|---|---|
| custom-network | 76% (27,5 / 36) | **100%** (36 / 36) |
| modern | 78% (25 / 32) | **91%** (29 / 32) |
| vulnerable | 2/4 usługi nazwane | **4/4** usługi nazwane, wersje WordPress i DVWA |

## Uczenie sygnatur z GUI (kreator „Naucz system”)

Nierozpoznane usługi z NPM nauczone w przeglądarce (szczegóły usługi → Naucz system):
- port 81 → „Nginx Proxy Manager”, kategoria: panel administracyjny (tytuł + favicon),
- port 80 → „Domyślna strona Nginx Proxy Manager”, kategoria: ciekawy artefakt.

Kolejny skan (#56) rozpoznał obie usługi: flagi panel-admin i artefakt, klasa portu 81 wzrosła z 4% do 28%.
Pokrycie stacku modern: **100%** (32 / 32).

## Stack 3: modern-proxy (Traefik → Toxiproxy → WordPress, opóźnienie 500 ms)

| Adres | Usługa AGH (port u AGH) | Co wykrył MoNet (skan #62) |
|---|---|---|
| 10.66.4.41:80 | WordPress przez Traefika (8085) | WordPress, kreator instalacji, **wolna odpowiedź (506 ms)**, **HTTP odsłonięty obok HTTPS** |
| 10.66.4.41:8080 | Dashboard Traefika (8086) | **Traefik dashboard** (sygnatura z kreatora po ścieżce `/dashboard/`), panel admina, HTTP+HTTPS |
| 10.66.4.42:8474 | API Toxiproxy (8474) | **Toxiproxy API** (ścieżka `/proxies`), panel admina bez logowania |

Scenariusz opóźnienia z README AGH: skan A bez opóźnienia (5–6 ms), skan B z opóźnieniem (505–506 ms).
Porównanie A→B: „czas odpowiedzi: 5 ms, szybka → 505 ms, wolniejsza” dla obu wejść do WordPressa. ✅

Funkcje dodane po teście (ogólne, nie pod jeden przypadek):
- **Czas odpowiedzi usługi:** pomiar pierwszej odpowiedzi bez kolejki limitera, kolumna w wynikach, flaga
  `wolna-odpowiedz` (≥ 500 ms) i zmiana przedziału czasu w porównaniu skanów.
- **Kreator „Naucz system” po ścieżce:** dla API i dashboardów, których strona główna zwraca 404.
- **Port dwuprotokołowy:** sonda sprawdza HTTP i HTTPS, ścieżki sygnatur próbuje w obu schematach. Usługa
  `http+https` i flaga `http-obok-https`, gdy HTTP serwuje treść zamiast przekierować na HTTPS.

Pokrycie: **67% → 100%** (15 / 15).
