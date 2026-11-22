# Formaty danych MoNet

## 1. Import celów

Cele można wpisać ręcznie albo zaimportować z pliku; oba sposoby przechodzą przez tę samą walidację.

Obsługiwane wartości: adres IPv4/IPv6 (`10.0.0.5`), CIDR (`10.0.0.0/16`, minimum /8), zakres (`10.0.0.1-10.0.0.50`
albo `10.0.0.1-50`), domena (`portal.example.pl`, rozwiązywana przez DNS w chwili utworzenia skanu).

**CSV** (separator `,` lub `;`, kodowanie UTF-8, opcjonalny BOM):

```csv
value,tags,note
10.10.0.0/16,kampus|dmz,sieć główna
192.168.5.1-40,lab,
portal.example.pl,www,serwis główny
```

Rozpoznawane nazwy kolumny celu: `value`, `target`, `ip`, `address`, `adres`, `cel`, `cidr`, `domain`, `host`.
Bez nagłówka pierwsza kolumna jest celem. Tagi rozdziela się znakiem `|` lub `;`.

**JSON**:

```json
["10.0.0.1", "10.0.1.0/24"]
```
```json
{"targets": [{"value": "10.0.0.0/24", "tags": ["dmz"], "note": "serwery"}]}
```

## 2. Eksport wyników (`asi-results/1`)

`GET /api/export/scan/{id}?format=json|csv`, `GET /api/export/services?format=json|csv`

```json
{
  "format": "asi-results/1",
  "exported_at": "2026-11-21T14:00:00Z",
  "scan": { "id": 3, "name": "Lab pełny · 2026-11-21 14:00", "ports": "21-23,80,443", "...": "..." },
  "live_hosts": ["10.66.8.1", "10.66.8.10"],
  "records": [
    {
      "ip": "10.66.8.10", "hostname": "staging1.lab.local", "port": 443, "proto": "tcp", "state": "open",
      "service": "http", "product": "nginx", "version": "1.25.3",
      "http_status": 200, "title": "STAGING – Portal", "server": "nginx/1.25.3", "tls": true,
      "cert_subject": "CN=staging.lab.local,O=Lab MoNet", "cert_not_after": "2026-12-11",
      "technologies": ["nginx 1.25.3 (100%)", "Środowisko testowe (treść) (90%)"],
      "flags": ["staging", "ujawniona-wersja"], "interest": 41,
      "headers": {"server": "nginx/1.25.3", "x-environment": "staging"},
      "cookies": ["PHPSESSID;HttpOnly"],
      "tags": ["do-weryfikacji"], "note": "notatka analityka"
    }
  ]
}
```

CSV ma te same pola (listy rozdzielone `|`): `ip, hostname, port, proto, state, service, product, version,
http_status, title, server, tls, cert_subject, cert_not_after, technologies, flags, interest, cookies, tags, note`.

## 3. Import wyników

`POST /api/import/results` (multipart, pole `file`, opcjonalnie `name`). Format jest rozpoznawany po treści:

| Format | Opis |
|---|---|
| XML nmapa | wynik `nmap -oX` (hosty `up` + otwarte porty z usługami) |
| JSON MoNet | dokument z punktu 2 albo sama tablica `records` |
| CSV MoNet | nagłówek z kolumną `ip` (pozostałe kolumny jak w eksporcie, wszystkie opcjonalne) |

Import tworzy skan typu „import”. Wyniki przechodzą przez sygnatury, ocenę ciekawości, aktualizację stanów hostów,
diff i eksport tak samo jak wyniki własnych skanów.

## 4. Porównanie skanów

`GET /api/diff?a={id}&b={id}` (bez parametrów: dwa ostatnie zakończone skany), eksport `GET /api/export/diff?a=&b=&format=json|csv`.

```json
{
  "a": {"id": 1, "...": "..."}, "b": {"id": 2, "...": "..."},
  "compared_ips": 16382, "compared_ports": "21-23,80,443",
  "summary": {"hosts_new": 3, "hosts_gone": 5, "services_new": 12, "services_gone": 9, "services_changed": 40},
  "hosts": [{"kind": "new", "ip": "10.66.9.4"}],
  "services": [{"kind": "changed", "ip": "10.66.8.20", "port": 80, "proto": "tcp",
                "changes": [{"field": "wersja", "before": "1.22.1", "after": "1.25.3"}]}],
  "notes": ["listy portów różnią się: porównano tylko wspólne porty"]
}
```

## 5. DefectDojo

`POST /api/dojo/push` (`{"scan_id": 3, "min_interest": 20}` albo `{"observation_ids": [..]}`) wysyła findingi
`Generic Findings Import` (severity `Info`, endpoint ip:port, tagi = flagi MoNet, opis z dowodami) na
`/api/v2/import-scan/` z `auto_create_context=true`. Ten sam plik można pobrać (`GET /api/dojo/preview?download=1`)
i zaimportować ręcznie w DefectDojo jako „Generic Findings Import”.

## 6. Sygnatury (YAML)

```yaml
id: moja-aplikacja            # unikalny identyfikator
name: Moja aplikacja
category: interesting         # cms|framework|server|appserver|iot|admin-panel|staging|devops|database|interesting|security|proxy|language|other
interest: 20                  # wkład w ocenę ciekawości
match: any                    # any | all
min_confidence: 0             # opcjonalny próg pewności (0-100)
matchers:
  - {type: header,  name: x-app,   regex: 'MojaApp/(?P<version>[\d.]+)', weight: 0.9}
  - {type: cookie,  name: '^MOJA_SESSION$', weight: 0.6}       # name = regex nazwy ciasteczka
  - {type: body,    regex: 'Powered by MojaApp', weight: 0.5}
  - {type: title,   regex: 'Moja Aplikacja', weight: 0.5}
  - {type: favicon, hashes: [-1234567890], weight: 0.8}         # mmh3 (format Shodan)
  - {type: path,    path: /version, status: [200], regex: '"version"', weight: 0.7}  # tylko GET, bez logowania
  - {type: banner,  regex: 'MojaApp', weight: 0.6}               # produkt/wersja/extrainfo z nmapa
  - {type: service, regex: '^http', weight: 0.2}
  - {type: cert,    regex: 'CN=moja', weight: 0.4}
  - {type: hostname, regex: '^moja\.', weight: 0.4}
  - {type: status,  status: [401], weight: 0.2}
  - {type: port,    ports: [8088], weight: 0.2}
```

Pewność detekcji to suma wag dopasowanych matcherów (maksymalnie 100%). Regexy są bez rozróżniania wielkości liter
(RE2). Matcher `negate: true` odwraca warunek.

## 7. Import sygnatur z pliku

Sygnatury → **Importuj z pliku** (albo `POST /api/signatures/import`, multipart: `file`, `mode=preview|import`,
`on_conflict=skip|overwrite`). Format jest rozpoznawany automatycznie:

| Format | Co jest importowane | Przykład |
|---|---|---|
| MoNet YAML / JSON | wszystko (format natywny, punkt 6) | eksport z `GET /api/signatures/export` |
| szablony nuclei | zapytania **GET** bez payloadów: `path`, matchery `word`/`regex` (body/header/title), `status`, favicon (`dsl: mmh3(...) == N`); `matchers-condition: and` | `docs/przyklady-sygnatur/nuclei-panele.yaml` |
| Wappalyzer (`technologies.json`) | `headers`, `cookies`, `html`/`text`, `scriptSrc`, `meta`, `url`; wersja z `\;version:\1`; kategoria z `cats` | `docs/przyklady-sygnatur/wappalyzer-technologies.json` |
| CSV | `name, type, pattern` + opcjonalnie `category, interest, header, path, status, weight`; wiele wierszy o tej samej nazwie = jedna sygnatura z wieloma matcherami | `docs/przyklady-sygnatur/proste.csv` |

Elementy niebezpieczne albo nieobsługiwane (POST, payloady, zmienne w ścieżkach, wzorce spoza składni RE2,
detekcja tylko po JavaScripcie) są pomijane i wypisywane jako ostrzeżenia w podglądzie. Import nie przerywa się z ich powodu.
