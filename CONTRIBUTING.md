# Współtworzenie projektu RaptorGate

Dziękujemy za zainteresowanie! Poniższe wytyczne pomogą utrzymać kod czysty i spójny.

## Spis treści

- [Wymagania wstępne](#wymagania-wstępne)
- [Konwencja nazewnictwa gałęzi](#konwencja-nazewnictwa-gałęzi)
- [Konwencja wiadomości commit](#konwencja-wiadomości-commit)
- [Przepływ pracy](#przepływ-pracy)
- [Wytyczne Pull Request](#wytyczne-pull-request)
- [Proces przeglądu kodu](#proces-przeglądu-kodu)
- [Pytania?](#pytania)

---

## Wymagania wstępne

- Git skonfigurowany z imieniem i e-mailem
- Dostęp do workspace Linear (organizacja RaptorGate)
- Znajomość [Conventional Commits](https://www.conventionalcommits.org/)

---

## Konwencja nazewnictwa gałęzi

### Format

```
<typ>/<issue-id>-<krótki-opis>
```

`{TEAM}` to jeden z: `FW` (firewall), `BE` (backend), `FE` (frontend), `INF` (infrastruktura)

### Typy gałęzi

| Prefiks | Gałąź docelowa | Zastosowanie |
|---|---|---|
| `feature/` | `development` | Nowa funkcjonalność |
| `bugfix/` | `development` | Naprawa błędu |
| `hotfix/` | `production` | Pilna poprawka produkcyjna (synchronizuj z `development` po scaleniu) |
| `refactor/` | `development` | Refaktoryzacja kodu |
| `docs/` | `development` | Dokumentacja |
| `chore/` | `development` | Narzędzia, zależności, konfiguracja |

### Przykłady

```
feature/FW-42-packet-filtering
bugfix/BE-12-grpc-reconnect
hotfix/FW-7-memory-leak
docs/INF-3-deployment-guide
refactor/BE-18-config-snapshot
```

### Zasady

- Tylko małe litery, słowa oddzielone myślnikami
- ID zgłoszenia w formacie `{TEAM}-XX` jest wymagane (np. `FW-42`, `BE-12`, `FE-7`, `INF-3`)

---

## Konwencja wiadomości commit

Zgodna z [Conventional Commits](https://www.conventionalcommits.org/):

```
<typ>(<zakres>): <temat>

<treść>

<stopka>
```

### Dozwolone typy

| Typ | Kiedy używać |
|---|---|
| `feat` | Nowa funkcjonalność |
| `fix` | Naprawa błędu |
| `docs` | Wyłącznie dokumentacja |
| `style` | Formatowanie, bez zmian logiki |
| `refactor` | Restrukturyzacja kodu bez zmiany zachowania |
| `perf` | Poprawa wydajności |
| `test` | Dodawanie lub poprawianie testów |
| `chore` | Zależności, narzędzia, konfiguracja budowania |
| `ci` | Konfiguracja CI/CD |

### Dozwolone zakresy

`firewall`, `packet-capture`, `docker`, `ci-cd`, `core`, `config`, `deps`

### Zasady

- Typ i zakres: małymi literami
- Temat: tryb rozkazujący (`add`, nie `added`), bez kropki na końcu, maks. 250 znaków
- Treść: wyjaśnia DLACZEGO, maks. 72 znaki na linię, poprzedzona pustą linią
- Stopka: `Closes #XX` lub `Fixes #XX`, poprzedzona pustą linią

### Przykłady

```
feat(firewall): add VLAN 802.1Q tag parsing

Parse 802.1Q tags in etherparse to support zone assignment per VLAN.
Enables filtering rules by VLAN ID in the policy engine.

Closes FW-77
```

```
fix(config): prevent stale snapshot after rollback

Redb snapshot was not updated when rollback applied a previous version,
causing emergency startup to load an outdated config.

Fixes BE-16
```

---

## Przepływ pracy

1. Wybierz zgłoszenie z Linear (np. `FW-42`, `BE-12`)
2. Utwórz gałąź z `development` zgodnie z konwencją nazewnictwa
3. Commituj używając formatu Conventional Commits
4. Otwórz Pull Request kierowany do `development`
5. Poproś o przeglądy zgodnie z wymaganiami poniżej

---

## Wytyczne Pull Request

### Przed otwarciem PR

- [ ] Gałąź zgodna z konwencją nazewnictwa: `feature/FW-XX-opis`
- [ ] Commity zgodne ze standardem Conventional Commits
- [ ] Testy przechodzą lokalnie
- [ ] Brak błędów lintera
- [ ] Kod sformatowany zgodnie z zasadami projektu

### Format tytułu PR

```
<typ>(<zakres>): <opis>
```

Przykład: `feat(firewall): add Aho-Corasick IPS signature matching`

---

## Proces przeglądu kodu

### Wymagania zatwierdzeń

| Gałąź | Wymagane zatwierdzenia |
|---|---|
| `production` | 4 |
| `staging` | 3 |
| `development` | 3 |

Wszystkie sprawdzenia CI (lint, testy, build) muszą przejść przed scaleniem.

### Dla recenzentów

- Uruchom kod lokalnie i przetestuj
- Sprawdź czy wiadomości commitów są zrozumiałe
- Zweryfikuj pokrycie testami
- Szukaj przypadków brzegowych
- Używaj "Suggest change" przy drobnych poprawkach

### Dla autorów

- Odpowiadaj na wszystkie komentarze
- Wprowadzaj uwagi w nowych commitach
- Oznaczaj rozmowy jako rozwiązane po zakończeniu
- Poproś ponownie o przegląd po zmianach

---

## Pytania?

- Otwórz zgłoszenie w Linear w formacie `{TEAM}-XX`
- Zapytaj na kanale projektu
