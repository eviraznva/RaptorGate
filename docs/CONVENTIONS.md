# Konwencje RaptorGate

## Nazewnictwo gałęzi

```
<typ>/<issue-id>-<krótki-opis>
```

`{TEAM}` to jeden z: `FW` | `BE` | `FE` | `INF`

| Prefiks | Gałąź docelowa | Zastosowanie |
|---|---|---|
| `feature/` | `development` | Nowa funkcjonalność |
| `bugfix/` | `development` | Naprawa błędu |
| `hotfix/` | `production` | Pilna poprawka |
| `refactor/` | `development` | Refaktoryzacja |
| `docs/` | `development` | Dokumentacja |
| `chore/` | `development` | Narzędzia, zależności |

**Przykłady:**
```
feature/FW-42-packet-filtering
bugfix/BE-12-grpc-reconnect
hotfix/FW-7-memory-leak
docs/INF-3-deployment-guide
```

**Zasady:** małe litery, słowa oddzielone myślnikami, ID zgłoszenia wymagane.

---

## Wiadomości commit

Format: `<typ>(<zakres>): <temat>`

### Typy

`feat` · `fix` · `docs` · `style` · `refactor` · `perf` · `test` · `chore` · `ci`

### Zakresy

`firewall` · `packet-capture` · `docker` · `ci-cd` · `core` · `config` · `deps`

### Zasady

- Typ i zakres: małymi literami
- Temat: tryb rozkazujący, bez kropki na końcu, maks. 250 znaków
- Treść: wyjaśnia DLACZEGO, maks. 72 znaki/linię, poprzedzona pustą linią
- Stopka: `Closes FW-42` lub `Fixes BE-12`, poprzedzona pustą linią

### Przykład

```
feat(firewall): add Aho-Corasick IPS signature matching

Replace linear scan with Aho-Corasick automaton for multi-pattern
matching. Reduces signature match time from ~10 µs to < 1 µs.

Closes FW-49
```

---

## Identyfikatory zgłoszeń Linear

| Zespół | Klucz | Obszar |
|---|---|---|
| Firewall | `FW` | Pipeline Rust, przetwarzanie pakietów, silnik polityk |
| Backend | `BE` | API NestJS/Bun, gRPC, zarządzanie konfiguracją |
| Frontend | `FE` | Panel administracyjny React/Vite |
| Infrastruktura | `INF` | Docker, CI/CD, testy, benchmarki |

Zgłoszenia w formacie `{TEAM}-XX`, np. `FW-42`, `BE-12`, `FE-7`, `INF-3`.

---

## Styl kodu

### Rust (Firewall)

- Edycja 2024
- `cargo fmt` i `cargo clippy --deny warnings` muszą przejść
- Obsługa błędów: `thiserror` dla bibliotek, `anyhow` dla binariów
- Brak `unwrap()` na ścieżkach produkcyjnych — propaguj błędy jawnie

### TypeScript (Backend / Frontend)

- Tryb ścisły włączony
- ESLint + Prettier skonfigurowane w każdym pakiecie
- NestJS: jeden moduł na domenę funkcjonalną
- React: wyłącznie komponenty funkcyjne z hookami

### Ogólne

- Brak zakomentowanego kodu w commitach
- Brak `TODO` bez powiązanego zgłoszenia w Linear
- Testy wymagane dla całej logiki biznesowej

---

## Wymagania przeglądu PR

| Gałąź | Wymagane zatwierdzenia |
|---|---|
| `production` | 4 |
| `staging` | 3 |
| `development` | 3 |

Wszystkie sprawdzenia CI (lint, testy, build) muszą przejść przed scaleniem.

---

## Wersjonowanie

Wersjonowanie semantyczne: `MAJOR.MINOR.PATCH`

- `MAJOR`: przełomowa zmiana API
- `MINOR`: nowa funkcjonalność, wstecznie kompatybilna
- `PATCH`: naprawa błędu

Tagi wyzwalają potok wydania CI/CD.
