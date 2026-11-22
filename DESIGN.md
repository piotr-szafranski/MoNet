# DESIGN.md: MoNet (Monitoring Network)

Źródło prawdy dla wyglądu interfejsu. Zbudowane według skilla `samber/cc-skills@frontend-design-deslop` (MIT).
Jeśli kod CSS rozjedzie się z tym plikiem, wygrywa ten plik.

## 1. Kontekst (Phase 0)

- **Artefakt:** dashboard / narzędzie danych, wariant operacyjny i analityczny (monitoring powierzchni ataku).
- **Dla kogo:** analitycy Centrum Bezpieczeństwa Informacji AGH; drugi odbiorca: jury HackNation (kilka minut na ocenę).
- **Decyzja, którą wspiera dashboard:** „co jest wystawione i wymaga uwagi teraz, i co zmieniło się od ostatniego skanu”.
- **Przymiotniki:** spokojny, instytucjonalny, czytelny (wybór zespołu, 22.11).
- **Esencja estetyki:** „spokojny rejestr operacyjny”.
- **Ograniczenia zespołu (mają pierwszeństwo przed wytycznymi ogólnymi):** krawędzie prostokątne; wyjątki zaokrąglone tylko dla
  przełącznika w stylu Apple, kropek statusu i wykrzyknika w menu. Jasny motyw wg `docs/biale ui.jpg`, ciemny domyślny.

## 2. System (Phase 1)

- **Kierunek:** instytucjonalny rejestr: neutralne płaszczyzny o chłodnym, stalowym odcieniu, cienkie linie podziału,
  zero ozdobników. Kolor wyłącznie dla znaczenia (stan, ważność), nigdy dla dekoracji.
- **Typografia:** IBM Plex Sans (tekst, nagłówki 600) + IBM Plex Mono (adresy IP, porty, liczby, wersje), lokalnie
  przez @fontsource (OFL). Skala 1.2 od 14 px: 12 · 14 · 17 · 20 · 24 · 29 (ciaśniejsza skala celowo: gęste dane).
  Etykiety 11 px, 600, rozstrzelenie .04em. Liczby w tabelach i kafelkach: `tabular-nums`.
- **Kolor (OKLCH, `web/src/index.css`, `:root` = ciemny, `html.light` = jasny):**

  | Rola | Ciemny | Jasny |
  |---|---|---|
  | bg | oklch(0.165 0.006 245) | oklch(0.955 0.004 240) |
  | panel (obszar treści) | oklch(0.145 0.005 245) | oklch(0.995 0.001 240) |
  | card / surface | oklch(0.175 0.006 245) | oklch(0.995 0.001 240) |
  | tile | oklch(0.205 0.007 245) | oklch(0.972 0.004 240) |
  | line | oklch(0.265 0.008 245) | oklch(0.905 0.006 240) |
  | text / muted | oklch(0.95 …) / oklch(0.67 …) | oklch(0.22 …) / oklch(0.5 …) |
  | accent (stalowy niebieski, H 236–238, poza pasmem indygo) | oklch(0.74 0.1 236) | oklch(0.5 0.12 238) |
  | ok / warn / err | oklch(0.72 0.13 152) / (0.78 0.13 78) / (0.68 0.17 27) | (0.52 …) / (0.58 …) / (0.55 0.19 27) |

  Proporcja ok. 60-30-10: neutralne płaszczyzny / tekst i linie / akcent. Czerwień tylko dla „wymaga działania”.
- **Odstępy:** baza 4 px; ciasno w grupach, szeroko między sekcjami (24 px).
- **Promień:** 0 (decyzja zespołu). **Cienie:** brak; elewacja przez jasność płaszczyzny i jedną linię krawędzi.
- **Znak rozpoznawczy:** **pasek werdyktu** na górze dashboardu: jedno zdanie decyzji („Wymaga uwagi: N usług wysokiej
  klasy…”), cztery liczby, które je uzasadniają (wysoka klasa, zmiany od ostatniego skanu, nowe technologie do oceny,
  hosty niewidziane > 48 h), czerwony kwadrat przy liczbach wymagających działania (kolor + kształt + liczba) i jedna akcja.

## 3. Warstwa rzemiosła (Phase 2)

- **Układ:** pasek boczny z sekcjami i wyszukiwarką („/” lub Ctrl/⌘+K) + jeden duży panel treści; na dashboardzie
  najpierw werdykt (reguła 3-30-300: 3 s werdykt, 30 s zmiany i flagi, 300 s pełne tabele).
- **Komponenty:** przyciski rangowane ważnością (główny: wypełniony tekstem; akcja dnia: akcent; reszta: neutralne),
  tabele z liczbami w Mono i lekkimi separatorami, puste stany z jednym zdaniem wyjaśnienia.
- **Ruch:** tylko kolor tła i przezroczystość, ≤ 200 ms, ease-out; `prefers-reduced-motion` respektowane.
- **Ikony:** jeden zestaw (lucide), jedna grubość linii; bez kafelków-ikon nad nagłówkami.
- **Ciemny motyw:** zaprojektowany (prawie czerń, złamana biel, jaśniejsza płaszczyzna = wyżej), bez świecących cieni.
- **Dostępność:** widoczny fokus (`:focus-visible`), kontrast tekstu ≥ 4.5:1, liczby nie tylko kolorem (znacznik kształtu).

## 4. Audyt slopu (wynik 22.11)

Zaliczone: brak indygo i gradientów, brak tekstu z gradientem, brak glassmorphismu i świecących cieni, brak siatek-
ozdobników, primary face ≠ Inter, liczby tabular-nums, kolor tylko dla znaczenia, zera neutralne, brak tryptyku
„wielka liczba + mała etykieta” jako jedynego układu (zastąpiony paskiem werdyktu z decyzją).
Do poprawy później: część etykiet wielkimi literami w starszych kartach; ikony przy nagłówkach kart.

## 4a. Dyrektywy UX „anti-AI-slop” (monitoring sieci, 22.11, wersja obowiązująca)

Nadpisują sekcję 2 tam, gdzie się różnią.

- **Paleta:** ciemny `#0B0D10` (tło) / `#111418` (panele) / `#181C22` (kafelki), linie `#27272A`;
  jasny `#F8F9FA` / `#FFFFFF` / `#F1F3F5`, linie `#E4E4E7`. Bez cieni; podział tylko linią 1 px i krokiem jasności.
- **Kolory stanu (jedyne nasycone):** OK `#10B981`, ostrzeżenie / zdegradowany `#F59E0B`, krytyczny / niedostępny `#EF4444`,
  informacja / zaznaczenie `#3B82F6` (także akcent przycisku akcji).
- **Promienie:** karty, pola, przyciski 4–6 px; plakietki i tagi 2 px; kropki statusu okrągłe.
- **Stan = kropka 7 px + słowo** (komponent `State`), nie duża plakietka. „Niestabilny” = ostrzeżenie (bursztyn).
- **Typografia:** baza 13 px; etykiety metadanych 11 px wielkimi literami, rozstrzelenie .08em; IBM Plex Mono dla IP,
  portów, wersji, liczb i **znaczników czasu** (`<time>`), wszędzie `tabular-nums`.
- **Tabele:** przyklejone nagłówki, podświetlenie wiersza, ciasne wiersze (7 px).
- **Zakazy:** glassmorphism (usunięty także z modala, panelu bocznego i powiadomień), poświaty, gradienty dekoracyjne,
  wykresy-ozdobniki bez osi i jednostek, marketingowe słownictwo.

## 5. Historia zmian

- 22.11: dyrektywy „anti-AI-slop” dla monitoringu sieci (paleta, kropki stanu, czas w mono, tabele).
- 22.11: pierwsza wersja (kierunek „spokojny, instytucjonalny, czytelny”, IBM Plex, OKLCH, pasek werdyktu).
