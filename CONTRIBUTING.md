# Współtworzenie projektu RaptorGate

Dziękujemy za zainteresowanie! Poniższe wytyczne pomogą utrzymać kod czysty i spójny.

## 📋 Spis Treści

- [Konwencja Nazewnictwa Gałęzi](#branch-naming-convention)
- [Konwencja Wiadomości Commit](#commit-message-convention)
- [Przepływ Git](#git-workflow)
- [Wytyczne Pull Request](#pull-request-guidelines)
- [Proces Przeglądu Kodu](#code-review-process)
- [Pytania?](#questions)
- [Zasoby](#resources)

---

<a id="branch-naming-convention"></a>
## 🌿 Konwencja Nazewnictwa Gałęzi

### Format

```
<type>/<issue-id>-<short-description>
```

### Typy

| Typ | Opis | Przykład |
|------|------|----------|
| `feature/` | Nowa funkcja | `feature/NGFW-42-packet-filtering` |
| `bugfix/` | Naprawa błędu | `bugfix/NGFW-15-crash-handler` |
| `hotfix/` | Pilna poprawka produkcyjna | `hotfix/NGFW-200-critical-security` |
| `refactor/` | Refaktoryzacja | `refactor/NGFW-88-cleanup-rules` |
| `docs/` | Dokumentacja | `docs/NGFW-5-deployment-guide` |
| `chore/` | Utrzymanie (zależności, konfiguracja)| `chore/NGFW-3-update-deps` |

### Zasady

- ✅ Używaj małych liter
- ✅ Oddzielaj słowa myślnikami
- ✅ Bądź konkretny (nie `feature/new` tylko `feature/NGFW-42-packet-filtering`)
- ✅ Dodaj link do zgłoszenia (issue), jeśli istnieje
- ❌ Nie używaj @mention'ów
- ❌ Nie używaj znaków specjalnych

### Przykłady

```bash
# ✅ DOBRY
git checkout -b feature/NGFW-42-add-ip-whitelist
git checkout -b bugfix/NGFW-15-fix-memory-leak
git checkout -b refactor/NGFW-88-extract-processor

# ❌ ZŁY
git checkout -b feature/new-stuff
git checkout -b fix-bug
git checkout -b @tymoteusz/my-feature
```

---

<a id="commit-message-convention"></a>
## 📝 Konwencja Wiadomości Commit

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Typy

| Typ | Opis | Kiedy |
|------|------|--------|
| `feat` | Nowa funkcja | Dodajesz nową funkcjonalność |
| `fix` | Naprawa błędu | Naprawiasz błąd |
| `docs` | Dokumentacja | Aktualizujesz dokumentację |
| `style` | Formatowanie | Zmiana formatowania (nie logiki!) |
| `refactor` | Refaktoryzacja | Zmieniasz kod bez zmian funckji |
| `perf` | Wydajność | Poprawiasz wydajność |
| `test` | Testy | Dodajesz/aktualizujesz testy |
| `chore` | Utrzymanie | Konserwacja zależności i konfiguracji |
| `ci` | CI/CD | GitHub Actions, potoki CI |

### Zakres (opcjonalnie)

```
firewall         - NGFW rules engine
packet-capture   - Packet sniffing module
docker           - Docker configuration
ci-cd            - GitHub Actions
```

### Zasady

- ✅ Temat małymi literami (z wyjątkiem nazw własnych)
- ✅ Temat w trybie rozkazującym ("add", nie "added" ani "adds")
- ✅ Nie dodawaj kropki na końcu tematu
- ✅ Treść wyjaśnia DLACZEGO, nie CO (CO widać w diffie)
- ✅ Referencja do zgłoszenia: `Fixes #42` lub `Closes #42`
- ❌ Nie pisz `git commit` w wiadomości commita
- ❌ Nie wklejaj dużych fragmentów wyjścia (logów, diffów)

### Przykłady

#### Prosta funkcjonalność
```
feat(firewall): add IP whitelist feature
```

#### Z opisem
```
feat(packet-capture): implement AF_PACKET raw socket

- Added raw socket initialization with proper error handling
- Implemented packet filtering based on protocol
- Added comprehensive logging for debugging

Closes #42
```

#### Naprawa błędu
```
fix(firewall): prevent crash on invalid rules

Previously, the firewall would crash (SIGSEGV) when
loading invalid rules. Now rules are validated before
loading, with detailed error messages.

Fixes #200
```

#### Refaktoryzacja
```
refactor(api): extract packet processor to separate module

No functional changes. Improves code organization by
moving packet processing logic to dedicated module.
This makes the codebase easier to test and maintain.
```

#### Dokumentacja
```
docs: add deployment guide to README

- Added production deployment steps
- Added troubleshooting section
- Added environment setup instructions
```

#### Wydajność
```
perf(packet-capture): optimize packet filtering

Use pre-compiled BPF filters instead of runtime
compilation. Improves capture performance by 40%.

Benchmark results:
- Before: 125k packets/sec
- After: 175k packets/sec
```

---

<a id="git-workflow"></a>
## 🔄 Przepływ Git

### Konfiguracja lokalnego środowiska

```bash
# 1. Klonowanie repozytorium
git clone https://github.com/eviraznva/RaptorGate.git
cd RaptorGate

# 2. Dodaj repozytorium nadrzędne (upstream), jeśli to fork
git remote add upstream https://github.com/eviraznva/RaptorGate.git

# 3. Utwórz lokalną gałąź development
git checkout development
git pull origin development
```

### Rozwój funkcjonalności

```bash
# 1. Utwórz gałąź feature na bazie development
git checkout development
git pull origin development
git checkout -b feature/NGFW-42-packet-filtering

# 2. Pracuj nad funkcjonalnością
# ... napisz kod ...

# 3. Zacommituj z poprawną wiadomością
git add .
git commit -m "feat(packet-capture): add AF_PACKET support"

# 4. Wypchnij do zdalnego repozytorium origin
git push origin feature/NGFW-42-packet-filtering

# 5. Otwórz PR (Pull Request) na GitHub
# - Wejdź na https://github.com/eviraznva/RaptorGate
# - Kliknij "New Pull Request"
# - Wybierz: feature/NGFW-42-packet-filtering → development
# - Uzupełnij szablon PR

# 6. Po scaleniu przejdź z powrotem na development
git checkout development
git pull origin development
```

### Wiele commitów w ramach jednej funkcjonalności

```bash
# Każdy commit powinien mieć sensowny zakres!
git commit -m "feat(firewall): add rule validation"
git commit -m "feat(firewall): implement rule loading"
git commit -m "test(firewall): add validation tests"

# Wszystkie zostaną złączone do jednego przy scalaniu (ustawienia GitHub)
```

### Hotfix (Awaria na produkcji)

```bash
# 1. Utwórz gałąź hotfix z gałęzi production
git checkout production
git pull origin production
git checkout -b hotfix/NGFW-200-critical-bug

# 2. Napraw problem
# ... popraw kod ...
git commit -m "fix(firewall): prevent vulnerability"

# 3. Wypchnij i otwórz PR
git push origin hotfix/NGFW-200-critical-bug
# PR: hotfix/NGFW-200-critical-bug → production

# 4. Po scaleniu do production scal także do development
git checkout development
git pull origin development
git merge production
git push origin development
```

### Aktualizowanie gałęzi

```bash
# Jeśli na development pojawiły się nowe zmiany podczas pracy
git fetch origin
git rebase origin/development

# Albo jeśli wolisz scalenie (merge)
git merge origin/development
```

### Przed wypchnięciem

```bash
# Sprawdź zmiany lokalnie
git status

# Jeśli repo ma testy/linter, uruchom je przed wypchnięciem zmian
```

---

<a id="pull-request-guidelines"></a>
## 🔀 Wytyczne Pull Request

### Przed otwarciem PR

- [ ] Gałąź jest zgodna z konwencją nazewnictwa: `feature/NGFW-XX-description`
- [ ] Wszystkie commity są zgodne ze standardem Conventional Commits
- [ ] Jeśli repozytorium ma testy, przechodzą lokalnie
- [ ] Jeśli repozytorium ma linter, nie zgłasza błędów
- [ ] Brak błędów/ostrzeżeń w konsoli
- [ ] Kod jest sformatowany zgodnie z zasadami repozytorium

### Format tytułu PR

```
<type>(<scope>): <description>
```

Przykłady:
```
feat(firewall): add IP whitelist feature
fix(packet-capture): resolve socket error
docs: add deployment guide
```

### Szablon opisu PR

Użyj automatycznie generowanego szablonu z `.github/pull_request_template.md`:

```markdown
## Description
<!-- Clear description of changes -->

## Related Issue
Fixes #42

## Type of Change
- [ ] Feature
- [ ] Bug fix
- [ ] Documentation
- [ ] Refactoring
- [ ] Performance

## Testing
<!-- How was this tested? -->

## Checklist
- [ ] Commits follow conventional commits
- [ ] Tests pass
- [ ] No breaking changes
- [ ] Documentation updated
```

---

<a id="code-review-process"></a>
## 👀 Proces Przeglądu Kodu

### Dla reviewerów

- ✅ Uruchom kod lokalnie i go przetestuj
- ✅ Sprawdź, czy wiadomości commitów są zrozumiałe
- ✅ Zweryfikuj, czy dodano testy
- ✅ Szukaj przypadków brzegowych
- ✅ Zadawaj pytania, jeśli coś jest niejasne
- ✅ Używaj "Suggest change" przy drobnych poprawkach

### Dla autorów

- ✅ Odpowiadaj na wszystkie komentarze
- ✅ Wprowadzaj uwagi w nowych commitach (bez wymuszonego pusha!)
- ✅ Bądź uprzejmy i otwarty na sugestie
- ✅ Oznaczaj rozmowy jako rozwiązane po zakończeniu
- ✅ Poproś ponownie o przegląd po zmianach

### Wymagania przeglądu

| Gałąź | Przeglądy | Auto-usuwanie |
|--------|-----------|---------------|
| `production` | 4 akceptacje | ❌ |
| `staging` | 3 akceptacje | ❌ |
| `development` | 3 akceptacje | ❌ |

---

<a id="questions"></a>
## 🆘 Pytania?

- Sprawdź istniejącą dokumentację w `docs/`
- Przejrzyj wcześniejsze PR-y i commity
- Zadaj pytanie w dyskusjach lub issue
- Skontaktuj się z @eviraznva

---

<a id="resources"></a>
## 📚 Zasoby

- [Conventional Commits](https://www.conventionalcommits.org/)

---

**Ostatnia aktualizacja:** marzec 2026
**Utrzymywane przez:** @eviraznva