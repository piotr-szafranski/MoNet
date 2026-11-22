# Integracja z DefectDojo

MoNet eksportuje wybrane obserwacje do DefectDojo jako **findingi informacyjne** (severity `Info`) z dowodami.
Do zarządzania podatnościami używa się wtedy narzędzia, które zespół już zna.

## Konfiguracja

1. W DefectDojo: *API v2 Key* (Profil użytkownika → API v2 Key) albo `POST /api/v2/api-token-auth/`.
2. W MoNet: **Import / eksport → Ustawienia DefectDojo** (rola Administrator): adres instancji, token, nazwa produktu
   i engagementu. Token jest zapisywany w bazie w postaci zaszyfrowanej (AES-256-GCM) i nigdy nie jest zwracany przez API.
3. „Test połączenia” wywołuje `GET /api/v2/products/?limit=1`.

## Wysyłka

- **Import / eksport → Eksport do DefectDojo**: skan (albo bieżący inwentarz) i minimalna ocena ciekawości.
- **Skany → szczegóły skanu → DefectDojo**: obserwacje z oceną ≥ 20.
- API: `POST /api/dojo/push` z `{"scan_id": 3, "min_interest": 20}` albo `{"observation_ids": [1, 2, 3]}`
  (uprawnienie `dojo.push`: Administrator, Operator).

MoNet wywołuje `POST /api/v2/import-scan/` z parametrami `scan_type=Generic Findings Import`,
`auto_create_context=true` (produkt i engagement tworzone automatycznie), `minimum_severity=Info`,
`deduplication_on_engagement=true`. Każdy finding zawiera:

| Pole | Zawartość |
|---|---|
| `title` | `[MoNet] ip:port/proto usługa – najciekawsza technologia` |
| `description` | usługa i wersja, ocena ciekawości, flagi, technologie z pewnością i dowodami, nagłówki HTTP, ciasteczka (flagi Secure/HttpOnly), certyfikat TLS |
| `endpoints` | host, port, protokół (`http`/`https`/`tcp`) |
| `tags` | `asi`, `discovery` + flagi MoNet (np. `panel-admin`, `staging`, `cert-wygasly`) |
| `unique_id_from_tool` | `asi-<ip>-<port>-<proto>` (deduplikacja przy kolejnych eksportach) |
| `component_name/version` | produkt i wersja usługi |

Bez połączenia sieciowego z DefectDojo można pobrać ten sam plik (**Pobierz plik do ręcznego importu**,
`GET /api/dojo/preview?download=1`) i zaimportować go w DefectDojo jako „Generic Findings Import”.

## Weryfikacja

Integrację przetestowano na lokalnej instancji DefectDojo 3.5 (oficjalny `docker-compose.yml`, obrazy z Docker Hub):
eksport 127 obserwacji z labu utworzył 127 findingów `Info` z tagami i endpointami w nowym produkcie i engagemencie.
Konfiguracja testowej instancji jest w `third_party/defectdojo/` (uruchomienie:
`docker-compose -p asi-dojo -f third_party/defectdojo/docker-compose.yml up -d --no-build`, port 8096).
