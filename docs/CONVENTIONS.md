# Konwencje Git i kodu źródłowego

Szczegółowy przewodnik po konwencjach nazewnictwa gałęzi i wiadomości commitów w projekcie RaptorGate.

---

## 🌿 Szczegółowy przewodnik nazewnictwa gałęzi

### Wzorzec nazewnictwa gałęzi

```
<type>/<issue-id>-<short-description>
```

**Komponenty:**
- `type` - Typ pracy (feature, bugfix, hotfix, refactor, docs, chore)
- `issue-id` - ID zgłoszenia (NGFW-42, opcjonalne, ale rekomendowane)
- `short-description` - Krótki opis w formacie kebab-case, maksymalnie 50 znaków

### Omówienie typów gałęzi

#### 1. `feature/*` - Nowe funkcjonalności

**Kiedy używać:**
- Dodajesz nową funkcjonalność
- Rozszerzasz istniejącą funkcjonalność
- Dodajesz nowy moduł

**Docelowa gałąź:** `development` (następnie → `staging` → `production`)

**Przykłady:**
```
feature/NGFW-42-packet-filtering
feature/NGFW-55-ip-whitelist-rules
feature/NGFW-63-blazor-dashboard
feature/NGFW-71-docker-compose-setup
```

**Przepływ:**
```
development ← feature/NGFW-42-packet-filtering (PR + scalenie)
  ↓ (później)
staging ← development (PR + scalenie)
  ↓ (później)
production ← staging (PR + scalenie, wydanie)
```

#### 2. `bugfix/*` - Poprawianie błędów

**Kiedy używać:**
- Naprawiasz błąd znaleziony w development lub staging
- Coś nie działa jak powinno
- Ale nie jest to awaria produkcyjna wymagająca natychmiastowej reakcji

**Docelowa gałąź:** `development` (standardowo)

**Przykłady:**
```
bugfix/NGFW-15-memory-leak-handler
bugfix/NGFW-28-crash-invalid-rules
bugfix/NGFW-91-docker-network-issue
```

**W porównaniu z `feature/*`:**
```
feature/NGFW-42-add-whitelist      ← Dodajesz nową funkcjonalność
bugfix/NGFW-42-fix-whitelist       ← Naprawiasz błąd w istniejącej funkcjonalności
```

#### 3. `hotfix/*` - Pilne poprawki produkcyjne

**Kiedy używać:**
- Występuje krytyczny błąd na produkcji
- Pojawia się problem bezpieczeństwa
- Istnieje ryzyko utraty danych
- Usługa nie działa

**Docelowa gałąź:** `production` BEZPOŚREDNIO! (następnie zmiany wracają do `development`)

**Przykłady:**
```
hotfix/NGFW-200-critical-security-vulnerability
hotfix/NGFW-205-production-crash
hotfix/NGFW-210-data-corruption
```

**Przepływ (wyjątkowy):**
```
production ← hotfix/NGFW-200 (pilny PR + scalenie)
  ↓ (synchronizacja zmian)
development ← przeniesienie zmian z hotfixa
```

#### 4. `refactor/*` - Ulepszanie kodu

**Kiedy używać:**
- Zmieniasz strukturę kodu
- Wydzielasz funkcje
- Spłacasz dług techniczny
- Reorganizujesz moduły
- **Bez zmian w funkcjonalności!**

**Docelowa gałąź:** `development`

**Przykłady:**
```
refactor/NGFW-88-extract-processor-module
refactor/NGFW-89-cleanup-firewall-rules
refactor/NGFW-90-reorganize-project-structure
refactor/NGFW-92-remove-dead-code
```

**Ważne:** `refactor` oznacza brak zmian w funkcjonalności.
```
❌ BAD:
refactor/cleanup (a zmienia logikę!)

✅ GOOD:
refactor/extract-module (czysty refactor, zero zmian)
```

#### 5. `docs/*` - Dokumentacja

**Kiedy używać:**
- Aktualizujesz README
- Dodajesz dokumentację
- Piszesz poradniki
- Dodajesz komentarze w kodzie
- Nie zmieniasz kodu aplikacji

**Docelowa gałąź:** `development` (lub czasem `production`, jeśli dokumentacja dotyczy wydania)

**Przykłady:**
```
docs/NGFW-5-deployment-guide
docs/add-architecture-diagram
docs/update-readme-setup
docs/add-troubleshooting-section
```

#### 6. `chore/*` - Utrzymanie i konfiguracja

**Kiedy używać:**
- Aktualizujesz zależności
- Zmieniasz workflow GitHub Actions
- Aktualizujesz konfigurację budowania
- Konfigurujesz Dockera
- Wprowadzasz drobne zmiany w CI/CD

**Docelowa gałąź:** `development`

**Przykłady:**
```
chore/NGFW-3-update-dependencies
chore/update-github-actions
chore/add-docker-compose
chore/upgrade-nodejs
chore/update-eslint-config
```

---

## 📝 Szczegółowy przewodnik po wiadomościach commitów

### Format standardu Conventional Commits

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Część 1: Typ

```
feat    - Nowa funkcjonalność
fix     - Naprawa błędu
docs    - Dokumentacja
style   - Formatowanie (nie zmienia logiki)
refactor - Refaktoryzacja (zmienia strukturę, funkcjonalność ta sama)
perf    - Optymalizacja wydajności
test    - Dodawanie/aktualizowanie testów
chore   - Utrzymanie (build, zależności, konfiguracja)
ci      - Zmiany w pipeline'ach CI/CD
```

**Zasady:**
- Zawsze używaj małych liter
- Jeden z listy wyżej
- Musi jasno wynikać, co zostało zrobione

### Część 2: Zakres (opcjonalnie)

```
firewall         - NGFW firewall rules
packet-capture   - Packet sniffing & capture
docker           - Docker & containerization
ci-cd            - GitHub Actions & pipelines
core             - Core application
config           - Configuration files
deps             - Dependencies
```

**Zasady:**
- Używaj małych liter
- Jeśli zakresu nie ma, pomiń nawiasy
- Zakres jest opcjonalny, ale zalecany

### Część 3: Temat

```
<subject line>
```

**Zasady:**
- Używaj trybu rozkazującego: `add`, a nie `added` czy `adds`
- Nie zaczynaj wielką literą, chyba że używasz nazwy własnej
- Nie stawiaj kropki na końcu
- Staraj się nie przekraczać około 250 znaków
- Pisz konkretnie i jasno

**Przykłady:**
```
✅ GOOD:
feat(firewall): add IP whitelist validation
fix(packet-capture): handle malformed packets
refactor(api): extract processor module

❌ BAD:
feat: new feature added
Fix bug in firewall
add stuff
```

### Część 4: Treść (wielolinijkowe commity)

Wyjaśnia **DLACZEGO**, nie CO (CO widać w diff'ie).

```
<empty line>

- Use bullet points for clarity
- Explain the motivation for the change
- Contrast with previous behavior
- Maximum 72 characters per line
```

**Przykłady:**

```
feat(firewall): add IP whitelist validation

- Add whitelist functionality to firewall rules
- Validate IPs against whitelist before processing
- Return error if IP not in whitelist

This improves security by allowing only trusted
IPs to pass through the firewall.

Closes #42
```

```
fix(packet-capture): handle malformed packets

Previously, malformed packets would cause SIGSEGV.
Now we validate packet format before processing.

- Added packet format validation
- Added detailed error logging
- Added test cases for edge cases

Fixes #200
```

### Część 5: Stopka (opcjonalnie)

```
<empty line>

Closes #42
Fixes #200
Relates to #15
Breaking change: description
Co-authored-by: name <email>
```

**Najczęstsze stopki:**
- `Closes #42` - zamyka zgłoszenie
- `Fixes #200` - oznacza naprawę błędu
- `Relates to #15` - wskazuje powiązanie ze zgłoszeniem, ale go nie zamyka
- `Breaking change:` - Jeśli zmienia public API
- `Co-authored-by:` - wielu autorów

---

## 🔗 Łączenie gałęzi z commitami

### Przykład przepływu

**Przykładowe zgłoszenie:** NGFW-42: "Add IP whitelist feature"

```bash
# 1. Utwórz gałąź na podstawie zgłoszenia
git checkout -b feature/NGFW-42-ip-whitelist

# 2. Pracuj i twórz commity
git commit -m "feat(firewall): add whitelist validator"
git commit -m "feat(firewall): implement rule loading"
git commit -m "test(firewall): add validator tests"

# 3. Wypchnij zmiany
git push origin feature/NGFW-42-ip-whitelist

# 4. Otwórz PR z odwołaniem do zgłoszenia
# Tytuł: feat(firewall): add IP whitelist feature
# Treść zawiera: Closes #42

# 5. Przy scaleniu wszystkie commity są squashowane (ustawienie GitHub)
# Końcowy commit: "feat(firewall): add IP whitelist feature"
# To zamyka zgłoszenie #42
```

---

## 📚 Przykłady praktyczne

### Przykład 1: Pełna funkcjonalność

```bash
# Gałąź
feature/NGFW-42-packet-filtering

# Commity (kilka w trakcie pracy)
feat(packet-capture): implement AF_PACKET raw socket
feat(packet-capture): add packet filtering logic
test(packet-capture): add unit tests
docs: update packet capture docs

# Po scaleniu → wszystko zostaje złączone do jednego commita
feat(packet-capture): implement AF_PACKET raw socket and filtering

# Closes #42
```

### Przykład 2: Naprawa błędu z analizą

```bash
# Gałąź
bugfix/NGFW-15-memory-leak

# Commity
fix(firewall): prevent memory leak in rule loader

Previously, rules were not freed when reloading.
This caused memory usage to grow with each reload.

Now:
- Properly deallocate old rules
- Added memory profiling test
- Verified with valgrind

# Closes #15
```

### Przykład 3: Hotfix na produkcję

```bash
# Gałąź
hotfix/NGFW-200-critical-vulnerability

# Commity
fix(firewall): patch security vulnerability CVE-2024-1234

Critical vulnerability in rule parsing allows
arbitrary code execution. This patch:

- Sanitizes rule input
- Validates all parameters
- Disables vulnerable code path

Should be deployed immediately!

# Closes #200
```

### Przykład 4: Refaktoryzacja

```bash
# Gałąź
refactor/NGFW-88-extract-processor

# Commity
refactor(api): extract packet processor to module

No functional changes. Improves code organization
by moving packet processing logic to dedicated
module. Makes codebase easier to test.

# Performance: no change
# Functionality: no change
# Code quality: improved
```

---

## 🛠️ Przydatne narzędzia

### Hooki pre-commit (opcjonalnie)

Utwórz `.husky/commit-msg`:

```bash
#!/bin/sh
# Validates commit message format
npx --no-install commitlint --edit "$1"
```

### Aliasy Git (opcjonalnie)

W `~/.gitconfig`:

```ini
[alias]
  co = checkout
  br = branch
  ci = commit
  st = status
  unstage = reset HEAD --
  last = log -1 HEAD
  visual = log --graph --oneline --all
```

Użycie:
```bash
git co feature/NGFW-42-my-feature
git ci -m "feat(firewall): add validation"
git visual
```

---

## 📋 Checklista przed PR

- [ ] Gałąź jest zgodna z konwencją nazewnictwa: `feature/NGFW-XX-description`
- [ ] Wszystkie commity są zgodne ze standardem Conventional Commits
- [ ] Jeśli repozytorium ma testy, przechodzą lokalnie
- [ ] Jeśli repozytorium ma linter, nie zgłasza błędów
- [ ] Brak błędów/ostrzeżeń w konsoli
- [ ] Kod jest sformatowany zgodnie z zasadami repozytorium

---

## 🆘 Częste błędy

| Błąd | Problem | Rozwiązanie |
|------|---------|-------------|
| `feature/new-stuff` | Zbyt ogólna nazwa | Użyj `feature/NGFW-42-add-filtering` |
| `add more code` | Brak prefiksu typu | Użyj `feat: add filtering logic` |
| `FIXED BUG` | Nieprawidłowa wielkość liter | Użyj `fix: prevent crash` |
| `feat(Firewall)` | Nieprawidłowa wielkość liter w zakresie | Użyj `feat(firewall)` |
| `feat: add filtering.` | Kropka na końcu | Usuń kropkę |
| `merge development` | Nieprawidłowy temat commita | Użyj `feat: add filtering` |
| Wiele wielkich liter | Gorsza czytelność | Użyj małych liter: `fix(firewall)` |

---

## 📖 Źródła

- [Conventional Commits](https://www.conventionalcommits.org)
- [Git Branching Model](https://nvie.com/posts/a-successful-git-branching-model/)
- [GitHub Flow](https://guides.github.com/introduction/flow/)

---

**Ostatnia aktualizacja:** marzec 2026
**Pytania?** Skontaktuj się z @eviraznva.