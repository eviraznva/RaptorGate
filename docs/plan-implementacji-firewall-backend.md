# Plan implementacji zmian backendu (RaptorGate)

## Kontekst analizy projektu
- Backend jest oparty o NestJS (warstwy: `presentation`, `application`, `domain`, `infrastructure`).
- Listy dla zasobów są obecnie zwracane bez paginacji i bez filtrów (pełny `findAll()`).
- Dane są trzymane w JSON DB (`backend/data/json-db/*`) przez repozytoria `Json*Repository`.
- Integracja gRPC już istnieje (`GrpcModule`, `RaptorGateController`), ale `getActiveConfig` nie zwraca jeszcze finalnej odpowiedzi (kończy się `NotImplementedException`).
- Operacje apply/rollback konfiguracji są realizowane w `ApplyConfigSnapshotUseCase` i `RollbackConfigUseCase`.

> Uwaga: w kodzie endpoint reguł to aktualnie `GET /rule`, a nie `GET /rules`.

---

## 1) Dodanie paginacji i filtrowania list
**Zakres:** `GET /zones`, `GET /nat`, `GET /rules` (`/rule` w kodzie), `GET /zone-pairs`  
**Odpowiedzialny:** Marek Matusik  
**Estymacja:** 7 h

### Krótki plan implementacji
1. Ujednolicić kontrakt query params dla list: `page`, `limit`, `sortBy`, `sortOrder` + filtry specyficzne dla zasobu.
2. Dodać DTO zapytań (`class-validator`) w `presentation/dtos` i podpiąć je przez `@Query()` w kontrolerach.
3. Rozszerzyć use-case’y `GetAll*UseCase`, by przyjmowały parametry paginacji/filtrowania.
4. Rozszerzyć interfejsy repozytoriów (`IZoneRepository`, `INatRulesRepository`, `IRulesRepository`, `IZonePairRepository`) o metodę wyszukiwania z kryteriami.
5. W repozytoriach JSON zaimplementować: filtrowanie -> sortowanie -> paginację (`skip/take`) + `total`.
6. Rozszerzyć response DTO o metadane: `pagination: { page, limit, total, totalPages }`.
7. Zaktualizować Swagger (`@ApiQuery`) i testy e2e dla scenariuszy granicznych (pusta lista, strona poza zakresem, niepoprawny filtr).

### Pojęcia teoretyczne
- **Paginacja offsetowa**: dzielenie listy na strony przez `offset/limit` (`page/limit`); prosta i czytelna, ale przy dużych danych może być wolniejsza.
- **Filtrowanie**: zawężanie zbioru po warunkach (np. `isActive`, `name`, `type`) przed paginacją.
- **Sortowanie deterministyczne**: stała kolejność wyników (np. `createdAt DESC`, a przy remisie po `id`), żeby strony były stabilne.
- **Kontrakt API**: jednolity format odpowiedzi i parametrów, niezależny od źródła danych (JSON DB/SQL).

---

## 2) Wysyłanie aktywnej konfiguracji firewalla przez gRPC po rollbacku i aktywacji
**Zakres:** po `apply` (aktywacja) i po `rollback`  
**Odpowiedzialny:** Marek Matusik  
**Estymacja:** 8 h

### Krótki plan implementacji
1. Dokończyć mapowanie `ConfigurationSnapshot` -> `ConfigResponse` w `RaptorGateController.getActiveConfig` (bez `NotImplementedException`).
2. Dodać port aplikacyjny `ConfigPushService` (application), a adapter infrastrukturalny gRPC/eventowy do notyfikacji firewalla o zmianie aktywnej konfiguracji.
3. Po udanym `ApplyConfigSnapshotUseCase` (gdy `isActive=true`) wywołać publikację zdarzenia/triggera sync.
4. Po udanym `RollbackConfigUseCase` wywołać ten sam mechanizm publikacji.
5. Zapewnić idempotencję i obsługę błędów (retry/backoff, logi z `correlationId`, brak rollbacku transakcji domenowej przez chwilowy błąd sieci).
6. Dodać testy integracyjne: aktywacja i rollback powodują wysłanie sygnału + poprawny `GetActiveConfig` zwraca spójny bundle.

### Pojęcia teoretyczne
- **gRPC**: binarny protokół RPC (Protobuf), szybki i typowany, dobry dla komunikacji backend-firewall.
- **Aktywna konfiguracja**: aktualnie obowiązujący snapshot, który firewall powinien stosować.
- **Event-driven sync**: po zmianie stanu emitujemy zdarzenie, a konsument (firewall) pobiera konfigurację.
- **Idempotencja**: wielokrotne przetworzenie tego samego triggera nie zmienia końcowego stanu.
- **Eventually consistent**: system może chwilowo być niespójny, ale przez retry/resync dochodzi do zgodności.

---

## 3) Import i eksport konfiguracji firewalla w formacie JSON
**Zakres:** API i logika import/export pełnego bundla konfiguracji  
**Odpowiedzialny:** Marek Matusik  
**Estymacja:** 5 h

### Krótki plan implementacji
1. Dodać endpointy np. `GET /config/export` i `POST /config/import` w `ConfigController`.
2. `export`: odczyt aktywnego snapshotu i zwrot znormalizowanego JSON (`bundle + metadata`).
3. `import`: walidacja schematu JSON (Zod/class-validator), kontrola wersji/checksum, wczytanie do `ConfigurationSnapshot`.
4. Dodać tryb importu:
   - `dryRun` (walidacja bez zapisu),
   - `activate` (utworzenie nowego snapshotu i aktywacja).
5. Przy `activate=true` uruchomić ten sam mechanizm wysyłki/sync co w pkt 2.
6. Dodać testy: poprawny import, błędny JSON, niezgodna wersja, eksport->import round-trip.

### Pojęcia teoretyczne
- **Serializacja JSON**: zamiana obiektów domenowych na przenośny format tekstowy.
- **Walidacja schematu**: sprawdzenie struktury i typów przed zapisem (ochrona przed uszkodzeniem konfiguracji).
- **Checksum (SHA-256)**: skrót do wykrywania zmian i weryfikacji integralności bundla.
- **Snapshot konfiguracji**: punktowy, wersjonowany stan konfiguracji możliwy do odtworzenia (rollback).
- **Round-trip**: eksport i ponowny import powinny dać semantycznie ten sam stan.

---

## Kryteria ukończenia (Definition of Done)
- Endpointy list wspierają paginację + filtrowanie + metadane paginacji.
- `GetActiveConfig` przez gRPC zwraca prawidłową odpowiedź protokołu, bez `NotImplementedException`.
- Po aktywacji i rollbacku konfiguracji firewall dostaje trigger synchronizacji.
- Import/export JSON działa z walidacją i testami pozytywnymi/negatywnymi.
- Swagger i testy e2e/integracyjne są zaktualizowane.
