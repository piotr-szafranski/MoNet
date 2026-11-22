# Zapiski z testów integracji z DefectDojo

Środowisko: lokalna instancja DefectDojo 3.5 (oficjalny `docker-compose.yml`, obrazy z Docker Hub), MoNet na labie
10.66.0.0/18 (~1500 symulowanych hostów). Eksport obserwacji z klasą ≥ 25% jako findingi `Info`
(Generic Findings Import). Każda wysyłka jest też zapisywana w MoNet: **Import / eksport → Historia wysyłek do DefectDojo**.

## Seria testów (21.11.2026, test DefectDojo „MoNet – zapiski testów”, #5)

| # | Operacja | Skan MoNet | Wysłano | Bez zmian | Nowe | Zamknięte | Przywrócone | Wniosek |
|---|---|---|---|---|---|---|---|---|
| 1 | reimport (pierwszy) | 7 | 530 | 0 | **530** | 0 | 0 | test utworzony, wszystkie obserwacje jako nowe findingi |
| 2 | reimport tego samego skanu | 7 | 530 | **530** | 0 | 0 | 0 | brak zmian w sieci, więc w DefectDojo też nic się nie zmienia (deduplikacja działa) |
| 3 | reimport po zmianie labu | 8 | 530 | 199 | 331 | 331 | 0 | zmieniły się wersje i tytuły na hostach: DefectDojo zamyka stare findingi i tworzy aktualne |
| 4 | reimport kolejnego skanu | 9 | 527 | 521 | 0 | 9 | 6 | 9 usług zniknęło (hosty niestabilne), 6 wróciło: DefectDojo **przywraca** findingi zamiast tworzyć duplikaty |
| 5 | import (nowy test) | 9 | 527 | 0 | 527 | 0 | 0 | tryb „import” zawsze zakłada nowy test (#6) |
| 6 | reimport skanu 9 ponownie | 9 | 527 | **527** | 0 | 0 | 0 | stabilność: ten sam wynik, zero zmian |

## Porównanie z diffem MoNet

| Para skanów | Diff MoNet (wszystkie usługi) | DefectDojo (obserwacje z klasą ≥ 25%) |
|---|---|---|
| 7 → 8 | 392 nowe, 34 znikające, 1526 zmienionych usług; 11 nowych i 12 znikających hostów | 331 findingów zamkniętych i zastąpionych, 199 bez zmian |
| 8 → 9 | 21 nowych, 25 znikających, 265 zmienionych usług; 7 nowych i 11 znikających hostów | 9 zamkniętych, 6 przywróconych, 521 bez zmian |

DefectDojo widzi tylko eksportowany podzbiór (klasa ≥ progu), dlatego liczby są mniejsze niż w diffie MoNet.
Kierunek zmian się zgadza: zmiana wersji lub tytułu usługi oznacza w DefectDojo zamknięcie starego findingu
i utworzenie nowego, a host niestabilny, który wrócił, oznacza przywrócenie findingu.

## Błędy znalezione dzięki testom (poprawione)

1. **Zmienne nagłówki w opisie** (`Date`, `ETag`, `Set-Cookie`…): DefectDojo deduplikuje po skrócie opisu, więc każdy
   reimport traktował wszystko jako nowe findingi. Te nagłówki są teraz pomijane w opisie.
2. **Losowa kolejność flag** w opisie: flagi są sortowane, więc opis jest deterministyczny.
3. **Podwojone liczniki w historii wysyłek:** DefectDojo zwraca poziomy ważności oraz pole `total`, a MoNet sumowało
   wszystko. Teraz bierze tylko `total`; wcześniejsze wpisy zostały skorygowane migracją.

## Jak powtórzyć

```bash
docker-compose -p asi-dojo -f third_party/defectdojo/docker-compose.yml up -d --no-build   # port 8096
# hasło admina: docker logs asi-dojo-initializer-1 | grep "Admin password"
# token: POST /api/v2/api-token-auth/ → wpisać w MoNet: Import / eksport → Ustawienia DefectDojo
```

Następnie w MoNet: Import / eksport → Eksport do DefectDojo (zaznaczony „reimport”) dla kolejnych skanów, a wyniki
odczytać w tabeli „Historia wysyłek do DefectDojo”. Instancja demo https://demo.defectdojo.org/ ma to samo API v2.
Wysyłka tam publikuje dane, więc używamy jej tylko za zgodą.
