# Identity Frontend – Testy Manualne

Zakres: weryfikacja wszystkich zakładek Identity we frontendzie NGFW – RADIUS, LDAP, Authentication Profiles, Portal, Admin Login, Sessions, Diagnostics.

**Wymaganie:** Zalogowany jako `admin` / `admin123` (lokalny break-glass, role `super_admin` + `admin` + `operator` + `viewer`).

---

## Spis treści

1. [Przygotowanie](#1-przygotowanie)
2. [RADIUS Profiles](#2-radius-profiles)
3. [LDAP Profiles](#3-ldap-profiles)
4. [Authentication Profiles](#4-authentication-profiles)
5. [Portal Settings](#5-portal-settings)
6. [Admin Login](#6-admin-login)
7. [Active Sessions](#7-active-sessions)
8. [Diagnostics](#8-diagnostics)

---

## 1. Przygotowanie

### 1.1 Otwórz frontend
- URL: `https://<r1-ip>/` (lub lokalnie przez `npm run dev` w `frontend/`)
- Zaloguj się: `admin` / `admin123`

### 1.2 Przejdź do Identity
- W lewym sidebarze kliknij **Identity**
- Powinieneś zobaczyć 7 zakładek: **RADIUS Profiles**, **LDAP Profiles**, **Authentication Profiles**, **Portal Settings**, **Admin Login**, **Active Sessions**, **Diagnostics**

### 1.3 Weryfikacja StatusBar
- W górnej części strony jest pasek STATUS z 6 kafelkami
- Sprawdź, czy pokazują poprawne liczby profili i nazwy aktywnych profili
- **Oczekiwany wynik:** Wszystkie kafelki mają dane (nie puste)

### 1.4 Konta i adresy do testów RADIUS/LDAP

Management frontend i captive portal używają innych ekranów logowania:

- Management frontend: `https://192.168.56.254/login`
- Captive portal: `https://192.168.10.254/portal/login`

Konta labowe:

| Cel | Login | Hasło | Źródło / grupa |
|-----|-------|-------|----------------|
| Lokalny admin awaryjny | `admin` | `admin123` | lokalna baza adminów |
| Admin zewnętrzny | `admin` | `admin1234` | RADIUS/LDAP, LDAP group `admins` |
| Użytkownik portalu | `user` | `user123` | RADIUS/LDAP, LDAP group `users` |
| Gość portalu | `guest` | `guest123` | RADIUS/LDAP, LDAP group `guests` |

Ważne rozróżnienie:

- Login do management frontendu przechodzi przez zakładkę **Admin Login** i wymaga **Admin role mapping**, np. `ldap_group = admins -> admin`.
- Login do captive portal przechodzi przez zakładkę **Portal Settings** i tworzy sesję identity widoczną w **Active Sessions**.
- `Group source = ldap` oznacza, że RADIUS/LDAP tylko uwierzytelnia, a grupy są czytane z LDAP.
- `Group source = radius_vsa` oznacza, że grupy muszą przyjść z atrybutów RADIUS, np. `Filter-Id`, `Class` albo VSA; LDAP nie powinien być użyty jako fallback.
- Do testów enforcementu portal powinien widzieć klienta jako `192.168.10.10`, więc test portalu najlepiej wykonać z `h1` albo z przeglądarki tunelowanej przez `h1`.

---

## 2. RADIUS Profiles

### ID-FE-RAD-01 – Wyświetlanie listy profili RADIUS
1. Wybierz zakładkę **RADIUS Profiles**
2. Sprawdź, czy lista pokazuje istniejące profile (np. `default-radius`)
3. Sprawdź czy każdy wiersz pokazuje: **Name**, **Endpoint** (`host:port`), **Reference** (secret ref), **Meta** (timeout/retries)
4. **Oczekiwany:** Lista nie jest pusta. Status `active` lub `disabled`.

### ID-FE-RAD-02 – Stworzenie nowego profilu RADIUS
1. Kliknij przycisk **New** (prawy górny róg panelu "RADIUS Profiles")
2. W formularzu "New RADIUS Profile" wpisz:
   - **Name:** `test-radius`
   - **Description:** `Profil testowy`
   - **Active:** ✓ (checkbox zaznaczony)
   - **Host:** `192.168.20.30`
   - **Port:** `1812`
   - **Timeout ms:** `3000`
   - **Retries:** `2`
   - **Shared secret ref:** `secret://identity/radius/test-radius` (powinno się auto-uzupełnić)
   - **Set shared secret:** `radiussecret`
   - **NAS IP:** _(puste)_
   - **NAS identifier:** _(puste)_
   - **Called station ID:** _(puste)_
3. Kliknij **Save**
4. **Oczekiwany:** Sukces, profil pojawia się na liście, StatusBar pokazuje odświeżoną liczbę.

### ID-FE-RAD-03 – Edycja profilu RADIUS
1. Na liście profili RADIUS znajdź `test-radius`
2. Kliknij **Edit**
3. Zmień **Host** na `10.0.0.1`
4. Kliknij **Save**
5. **Oczekiwany:** Sukces, host w liście zmieniony na `10.0.0.1:1812`.
6. Przywróć host na `192.168.20.30` (Edit → Save).

### ID-FE-RAD-04 – Walidacja: tworzenie bez nazwy
1. Kliknij **New**
2. Zostaw **Name** puste, wypełnij tylko Host i Port
3. Kliknij **Save**
4. **Oczekiwany:** Błąd walidacji (backend zwróci 400).

### ID-FE-RAD-05 – Walidacja: duplikat nazwy profilu
1. Kliknij **New**
2. **Name:** `default-radius` (już istnieje)
3. Podaj inne wymagane pola, kliknij **Save**
4. **Oczekiwany:** Błąd 409 Conflict (`Identity profile conflict`).

### ID-FE-RAD-06 – Usuwanie profilu RADIUS
1. Na liście znajdź `test-radius`
2. Kliknij **Delete**
3. Confirm dialog: potwierdź
4. **Oczekiwany:** Sukces, profil znika z listy.

### ID-FE-RAD-07 – Usuwanie profilu w użyciu → 409
1. Spróbuj usunąć `default-radius` (jeśli jest używany przez auth profile)
2. **Oczekiwany:** Błąd 409 – `RADIUS server profile is in use`.

### ID-FE-RAD-08 – Anulowanie tworzenia profilu
1. Kliknij **New**
2. Wpisz kilka pól
3. Kliknij **Cancel**
4. **Oczekiwany:** Formularz się czyści, nic nie zostaje dodane.

---

## 3. LDAP Profiles

### ID-FE-LDAP-01 – Wyświetlanie listy profili LDAP
1. Wybierz zakładkę **LDAP Profiles**
2. Sprawdź, czy lista pokazuje istniejące profile (np. `default-ldap` jeśli LDAP enabled)
3. **Oczekiwany:** Lista nie jest pusta (gdy LDAP enabled) lub pokazuje "No LDAP profiles".

### ID-FE-LDAP-02 – Stworzenie nowego profilu LDAP
1. Kliknij **New**
2. Wpisz:
   - **Name:** `test-ldap`
   - **Active:** ✓
   - **Host:** `192.168.20.40`
   - **Port:** `389`
   - **TLS mode:** `disabled`
   - **Bind DN:** `cn=admin,dc=raptorgate,dc=local`
   - **Bind password ref:** `secret://identity/ldap/test-ldap`
   - **Set bind password:** `admin`
   - **User base DN:** `ou=users,dc=raptorgate,dc=local`
   - **User filter attribute:** `uid`
   - **Group base DN:** `ou=groups,dc=raptorgate,dc=local`
   - **Group member attribute:** `memberUid`
   - **Group name attribute:** `cn`
   - **Timeout ms:** `3000`
   - **Cache TTL seconds:** `60`
3. Kliknij **Save**
4. **Oczekiwany:** Sukces, profil na liście.

### ID-FE-LDAP-03 – Edycja profilu LDAP
1. Na liście znajdź `test-ldap`, kliknij **Edit**
2. Zmień **Port** na `636` i **TLS mode** na `starttls`
3. Kliknij **Save**
4. **Oczekiwany:** Sukces, wartości zmienione na liście.
5. Przywróć poprzednie wartości (Edit → Save).

### ID-FE-LDAP-04 – Walidacja: pusty Bind DN
1. Kliknij **New**
2. Zostaw **Bind DN** puste, resztę wypełnij
3. Kliknij **Save**
4. **Oczekiwany:** Błąd walidacji 400.

### ID-FE-LDAP-05 – Usuwanie profilu LDAP
1. Znajdź `test-ldap`, kliknij **Delete**, potwierdź
2. **Oczekiwany:** Sukces, profil znika.

### ID-FE-LDAP-06 – Anulowanie operacji
1. Kliknij **New**, wpisz dane, kliknij **Cancel**
2. **Oczekiwany:** Formularz się czyści, nic nie dodane.

---

## 4. Authentication Profiles

### ID-FE-AUTH-01 – Wyświetlanie listy profili uwierzytelniania
1. Wybierz zakładkę **Authentication Profiles**
2. Sprawdź listę – powinien być przynajmniej `default-portal-radius`
3. Kolumny: **Name**, **Endpoint** (provider + groupSource), **Reference** (RADIUS/LDAP), **Meta** (TTL + role mappings)
4. **Oczekiwany:** Lista nie jest pusta, dane się zgadzają.

### ID-FE-AUTH-02 – Stworzenie profilu z provider=RADIUS
1. Kliknij **New**
2. Wpisz:
   - **Name:** `test-auth-radius`
   - **Active:** ✓
   - **Provider:** `radius`
   - **RADIUS profile:** wybierz `default-radius` z dropdownu
   - **LDAP profile:** _(puste)_
   - **Group source:** `radius_vsa`
   - **Session TTL:** `1800`
   - **Admin role mappings:** _(puste)_
3. Kliknij **Save**
4. **Oczekiwany:** Sukces, profil na liście.

### ID-FE-AUTH-03 – Stworzenie profilu z provider=LDAP
1. Kliknij **New**
2. Wpisz:
   - **Name:** `test-auth-ldap`
   - **Provider:** `ldap`
   - **LDAP profile:** wybierz `default-ldap` (jeśli istnieje)
   - **RADIUS profile:** _(puste)_
   - **Group source:** `ldap`
   - **Session TTL:** `3600`
3. Kliknij **Save**
4. **Oczekiwany:** Sukces. Profile pojawiają się jako "ldap / groups: ldap".

### ID-FE-AUTH-04 – Stworzenie profilu z provider=local
1. Kliknij **New**
2. Wpisz:
   - **Name:** `test-auth-local`
   - **Provider:** `local`
   - **Group source:** `none`
   - **Session TTL:** `600`
3. **Oczekiwany:** Sukces. "local / groups: none".

### ID-FE-AUTH-05 – Profile z adminRoleMappings
1. Kliknij **New**
2. Wpisz:
   - **Name:** `test-auth-admin-role`
   - **Provider:** `radius`
   - **RADIUS profile:** `default-radius`
   - **Group source:** `ldap`
   - **LDAP profile:** `default-ldap` (jeśli istnieje)
3. W sekcji **Admin Role Mappings**:
   - Kliknij **Add mapping**
   - **Match type:** `ldap_group`
   - **Match value:** `admins`
   - **Role:** `admin`
   - Kliknij **Add mapping** ponownie
   - **Match type:** `username`
   - **Match value:** `superuser`
   - **Role:** `super_admin`
4. Kliknij **Save**
5. **Oczekiwany:** Sukces. Na liście widać "2 role mappings".

### ID-FE-AUTH-06 – Edycja profilu – zmiana providera i dodanie role mapping
1. Znajdź `test-auth-radius`, kliknij **Edit**
2. Zmień **Provider** z `radius` na `local`
3. Dodaj **Admin role mapping**: `username` = `admin`, role = `super_admin`
4. Kliknij **Save**
5. **Oczekiwany:** Sukces, profil zmieniony. Na liście widać "local / groups: radius_vsa" i "1 role mapping".

### ID-FE-AUTH-07 – Walidacja: provider=RADIUS bez wybranego profilu RADIUS
1. Kliknij **New**, wybierz provider=`radius`, zostaw RADIUS profile puste
2. Kliknij **Save**
3. **Oczekiwany:** Błąd 400.

### ID-FE-AUTH-08 – Walidacja: provider=LDAP bez profilu LDAP
1. Kliknij **New**, provider=`ldap`, LDAP profile puste
2. Kliknij **Save**
3. **Oczekiwany:** Błąd 400.

### ID-FE-AUTH-09 – Usuwanie profilu używanego przez Portal → 409
1. Spróbuj usunąć `default-portal-radius` (jeśli ustawiony jako portal w zakładce Portal Settings)
2. **Oczekiwany:** Błąd 409 – `Authentication profile is in use`.

### ID-FE-AUTH-10 – Usuwanie profilu używanego przez Admin Login → 409
1. Ustaw `test-auth-radius` jako admin auth profile (zakładka Admin Login → Save)
2. Wróć do Authentication Profiles, spróbuj usunąć `test-auth-radius`
3. **Oczekiwany:** 409 – `identity settings adminAuthenticationProfileId`.
4. Przywróć Admin Login na poprzedni profil.

### ID-FE-AUTH-11 – Usuwanie nieużywanego profilu
1. Usuń `test-auth-radius` (jeśli nie jest już w użyciu)
2. **Oczekiwany:** Sukces.

### ID-FE-AUTH-12 – Sprzątanie profili testowych
1. Usuń wszystkie testowe profile: `test-auth-radius`, `test-auth-ldap`, `test-auth-local`, `test-auth-admin-role`
2. **Oczekiwany:** Wszystkie usunięte (chyba że któryś jest w użyciu – wtedy najpierw odepnij).

---

## 5. Portal Settings

### ID-FE-PORT-01 – Wyświetlanie ustawień portalu
1. Wybierz zakładkę **Portal Settings**
2. Sprawdź, czy widać:
   - **Authentication profile** – dropdown z listą profili
   - **Portal listener** – enabled/disabled, interface, bind address, port
3. **Oczekiwany:** Pola załadowane z bieżącą konfiguracją.

### ID-FE-PORT-02 – Zmiana profilu portalu
1. Wybierz inny auth profile z dropdownu (np. `test-auth-local` – stwórz go najpierw jeśli nie istnieje)
2. Kliknij **Save**
3. **Oczekiwany:** Sukces. StatusBar pokazuje nową nazwę w "PORTAL".

### ID-FE-PORT-03 – Wyłączenie portalu (null profile)
1. Wybierz pustą opcję w dropdownie (jeśli dostępna, albo wybierz `null`/`None`)
2. Kliknij **Save**
3. **Oczekiwany:** Sukces. Portal wyłączony – status "None" w StatusBar.
4. Przywróć `default-portal-radius` jako portal profile.

### ID-FE-PORT-04 – Konfiguracja portalu listenera
1. W sekcji **Portal Listener**:
   - **Enabled:** ✓
   - **Interface:** _(nazwa interfejsu sieciowego, np. `eth1`)_
   - **Zone ID:** _(opcjonalnie – UUID strefy)_
   - **Bind address:** _(np. `192.168.10.254`)_
   - **Bind port:** `443`
2. Kliknij **Save**
3. **Oczekiwany:** Sukces.

### ID-FE-PORT-05 – Wyłączony listener
1. Odznacz **Enabled** w Portal Listener
2. Kliknij **Save**
3. **Oczekiwany:** Sukces, listener wyłączony.
4. Przywróć poprzednie ustawienia.

### ID-FE-PORT-06 – Logowanie do captive portal przez RADIUS + LDAP groups
1. Upewnij się, że istnieją profile:
   - RADIUS: `default-radius` albo profil testowy z hostem `192.168.20.30`, portem `1812` i sekretem `radiussecret`
   - LDAP: `default-ldap` albo profil testowy z hostem `192.168.20.40`, portem `389`, bind DN `cn=admin,dc=raptorgate,dc=local`, hasłem `admin` i `Group member attribute = memberUid`
2. W **Authentication Profiles** utwórz lub zaktualizuj profil:
   - **Name:** `test-portal-radius-ldap-groups`
   - **Provider:** `radius`
   - **RADIUS profile:** profil RADIUS z kroku 1
   - **LDAP profile:** profil LDAP z kroku 1
   - **Group source:** `ldap`
   - **Session TTL:** `300`
   - **Admin role mappings:** puste
3. W **Portal Settings** wybierz `test-portal-radius-ldap-groups`.
4. Ustaw listener:
   - **Enabled:** ✓
   - **Interface:** `eth1`
   - **Bind address:** `192.168.10.254`
   - **Bind port:** `443`
5. Kliknij **Save**.
6. Otwórz `https://192.168.10.254/portal/login`.
7. Zaloguj się jako `user` / `user123`.
8. Przejdź do **Active Sessions**.
9. **Oczekiwany:** Widać sesję `user`, `authenticated = true`, grupa zawiera `users`; przy teście z `h1` source IP powinien być `192.168.10.10`.

### ID-FE-PORT-07 – Logowanie do captive portal przez LDAP
1. W **Authentication Profiles** utwórz lub zaktualizuj profil:
   - **Name:** `test-portal-ldap`
   - **Provider:** `ldap`
   - **RADIUS profile:** puste
   - **LDAP profile:** profil LDAP z `Group member attribute = memberUid`
   - **Group source:** `ldap`
   - **Session TTL:** `300`
   - **Admin role mappings:** puste
2. W **Portal Settings** wybierz `test-portal-ldap` i kliknij **Save**.
3. Otwórz `https://192.168.10.254/portal/login`.
4. Zaloguj się jako `user` / `user123`.
5. Przejdź do **Active Sessions**.
6. **Oczekiwany:** Widać sesję `user`, `authenticated = true`, grupa zawiera `users`.

### ID-FE-PORT-08 – Portal przyjmuje gościa, ale sesja ma grupę `guests`
1. Użyj profilu portalowego z ID-FE-PORT-06 albo ID-FE-PORT-07.
2. Wyloguj lub zrewokuj poprzednią sesję `user`.
3. Otwórz `https://192.168.10.254/portal/login`.
4. Zaloguj się jako `guest` / `guest123`.
5. Przejdź do **Active Sessions**.
6. **Oczekiwany:** Login jest poprawny, ale sesja ma grupę `guests`. Jeśli aktywna polityka przepuszcza tylko `identity_group = "users"`, ruch gościa powinien zostać zablokowany.

### ID-FE-PORT-09 – Logowanie do captive portal przez RADIUS z `groupSource = radius_vsa`
1. Upewnij się, że profil RADIUS wskazuje serwer `192.168.20.30:1812` z sekretem `radiussecret`.
2. Upewnij się, że serwer RADIUS zwraca grupy w atrybutach RADIUS dla testowanego użytkownika:
   - `user` powinien zwracać grupę `users`
   - `guest` powinien zwracać grupę `guests`
3. W **Authentication Profiles** utwórz lub zaktualizuj profil:
   - **Name:** `test-portal-radius-vsa`
   - **Provider:** `radius`
   - **RADIUS profile:** profil RADIUS z kroku 1
   - **LDAP profile:** puste
   - **Group source:** `radius_vsa`
   - **Session TTL:** `300`
   - **Admin role mappings:** puste
4. W **Portal Settings** wybierz `test-portal-radius-vsa` i kliknij **Save**.
5. Otwórz `https://192.168.10.254/portal/login`.
6. Zaloguj się jako `user` / `user123`.
7. Przejdź do **Active Sessions**.
8. **Oczekiwany:** Sesja `user` jest aktywna, a grupy pochodzą z RADIUS i zawierają `users`. Jeśli RADIUS nie zwraca grup, sesja może być aktywna z pustą listą grup; wtedy polityka oparta o `identity_group = "users"` ma blokować ruch.

### ID-FE-PORT-10 – `radius_vsa` nie używa LDAP jako fallbacku
1. Zostaw aktywny profil `test-portal-radius-vsa` z ID-FE-PORT-09.
2. Wyloguj lub zrewokuj poprzednią sesję.
3. Tymczasowo użyj RADIUS usera, dla którego RADIUS robi Access-Accept, ale nie zwraca grup w `Filter-Id`/`Class`/VSA.
4. Zaloguj się w portalu tym użytkownikiem.
5. Przejdź do **Active Sessions**.
6. **Oczekiwany:** Login może się udać, ale grupy są puste albo zawierają tylko wartości z RADIUS. Backend nie powinien dociągnąć grup z LDAP tylko dlatego, że taki sam użytkownik istnieje w LDAP.

---

## 6. Admin Login

### ID-FE-ADM-01 – Wyświetlanie ustawień admin login
1. Wybierz zakładkę **Admin Login**
2. Sprawdź dropdown z auth profile'ami
3. **Oczekiwany:** Pokazuje tylko profile NIE będące `local` (czyli radius/ldap) + profil aktualnie ustawiony jako admin (nawet jeśli local).

### ID-FE-ADM-02 – Zmiana profilu admina na zewnętrzny (RADIUS)
1. Wybierz `default-portal-radius` (lub inny RADIUS/LDAP profile)
2. Kliknij **Save**
3. **Oczekiwany:** Sukces. StatusBar pokazuje nową nazwę w "ADMIN".

### ID-FE-ADM-03 – Wyłączenie zewnętrznego admina (null)
1. Wybierz pustą opcję w dropdownie
2. Kliknij **Save**
3. **Oczekiwany:** Sukces. Tylko lokalny break-glass admin dostępny.

### ID-FE-ADM-04 – Próba ustawienia profilu local jako admin (jeśli backend waliduje)
1. Stwórz profil auth z provider=`local` (patrz ID-FE-AUTH-04)
2. W Admin Login spróbuj wybrać ten profil
3. Kliknij **Save**
4. **Oczekiwany:** Backend zwróci błąd (profile `local` nie są dozwolone dla admin login).

### ID-FE-ADM-05 – Logowanie do management frontendu przez RADIUS
1. W **Authentication Profiles** utwórz lub zaktualizuj profil:
   - **Name:** `test-admin-radius-ldap-groups`
   - **Provider:** `radius`
   - **RADIUS profile:** profil RADIUS z hostem `192.168.20.30`, portem `1812` i sekretem `radiussecret`
   - **LDAP profile:** profil LDAP z hostem `192.168.20.40` i `Group member attribute = memberUid`
   - **Group source:** `ldap`
   - **Session TTL:** `300`
2. W sekcji **Admin role mappings** dodaj:
   - **Match type:** `ldap_group`
   - **Match value:** `admins`
   - **Role:** `admin`
3. Kliknij **Save**.
4. W **Admin Login** wybierz `test-admin-radius-ldap-groups` i kliknij **Save**.
5. Wyloguj się z management frontendu.
6. Otwórz `https://192.168.56.254/login`.
7. Zaloguj się jako `admin` / `admin1234`.
8. **Oczekiwany:** Login przechodzi, dashboard jest dostępny, a sesja admina ma rolę `admin`.

### ID-FE-ADM-06 – Logowanie do management frontendu przez LDAP
1. W **Authentication Profiles** utwórz lub zaktualizuj profil:
   - **Name:** `test-admin-ldap`
   - **Provider:** `ldap`
   - **RADIUS profile:** puste
   - **LDAP profile:** profil LDAP z hostem `192.168.20.40` i `Group member attribute = memberUid`
   - **Group source:** `ldap`
   - **Session TTL:** `300`
2. W sekcji **Admin role mappings** dodaj:
   - **Match type:** `ldap_group`
   - **Match value:** `admins`
   - **Role:** `admin`
3. Kliknij **Save**.
4. W **Admin Login** wybierz `test-admin-ldap` i kliknij **Save**.
5. Wyloguj się z management frontendu.
6. Otwórz `https://192.168.56.254/login`.
7. Zaloguj się jako `admin` / `admin1234`.
8. **Oczekiwany:** Login przechodzi, dashboard jest dostępny, a sesja admina ma rolę `admin`.

### ID-FE-ADM-07 – Zwykły użytkownik nie dostaje dostępu do management frontendu
1. Zostaw aktywny profil z ID-FE-ADM-05 albo ID-FE-ADM-06.
2. Wyloguj się z management frontendu.
3. Otwórz `https://192.168.56.254/login`.
4. Spróbuj zalogować się jako `user` / `user123`.
5. **Oczekiwany:** Uwierzytelnienie może zostać zaakceptowane przez RADIUS/LDAP, ale login do panelu admina jest odrzucony, bo `user` nie pasuje do mappingu `ldap_group = admins`.

### ID-FE-ADM-08 – Logowanie do management frontendu przez RADIUS z `groupSource = radius_vsa`
1. Upewnij się, że profil RADIUS wskazuje serwer `192.168.20.30:1812` z sekretem `radiussecret`.
2. Upewnij się, że RADIUS dla `admin` / `admin1234` zwraca grupę `admins` w atrybutach RADIUS.
3. W **Authentication Profiles** utwórz lub zaktualizuj profil:
   - **Name:** `test-admin-radius-vsa`
   - **Provider:** `radius`
   - **RADIUS profile:** profil RADIUS z kroku 1
   - **LDAP profile:** puste
   - **Group source:** `radius_vsa`
   - **Session TTL:** `300`
4. W sekcji **Admin role mappings** dodaj:
   - **Match type:** `radius_vsa`
   - **Match value:** `admins`
   - **Role:** `admin`
5. Kliknij **Save**.
6. W **Admin Login** wybierz `test-admin-radius-vsa` i kliknij **Save**.
7. Wyloguj się z management frontendu.
8. Otwórz `https://192.168.56.254/login`.
9. Zaloguj się jako `admin` / `admin1234`.
10. **Oczekiwany:** Jeśli RADIUS zwrócił `admins`, login przechodzi i sesja admina ma rolę `admin`. Jeśli RADIUS nie zwraca grup, login zewnętrzny jest odrzucony mimo poprawnego hasła, bo mapping `radius_vsa = admins` nie ma czego dopasować.

### ID-FE-ADM-09 – `radius_vsa` nie używa LDAP group mappingu
1. Zostaw aktywny profil `test-admin-radius-vsa`.
2. W profilu ustaw albo zostaw tylko mapping:
   - **Match type:** `ldap_group`
   - **Match value:** `admins`
   - **Role:** `admin`
3. Upewnij się, że **Group source** nadal ma wartość `radius_vsa`.
4. Wyloguj się z management frontendu.
5. Spróbuj zalogować się jako `admin` / `admin1234`.
6. **Oczekiwany:** Login jest odrzucony, jeżeli profil ma tylko mapping `ldap_group`. Przy `groupSource = radius_vsa` poprawny mapping dla grup z RADIUS to `matchType = radius_vsa`.

### ID-FE-ADM-10 – Przywrócenie domyślnych ustawień
1. Ustaw Admin Login na `null` (lub poprzedni profil)
2. Kliknij **Save**
3. **Oczekiwany:** Sukces.

---

## 7. Active Sessions

### ID-FE-SES-01 – Wyświetlanie listy aktywnych sesji
1. Wybierz zakładkę **Active Sessions**
2. Sprawdź, czy tabela pokazuje sesje z polami: username, source IP, groups, authenticated, expires
3. **Oczekiwany:** Lista jest widoczna (może być pusta jeśli brak aktywnych sesji). Auto-odświeżanie co 15s.

### ID-FE-SES-02 – Odświeżanie listy sesji
1. Kliknij przycisk **Refresh**
2. **Oczekiwany:** Lista się odświeża (ikona ładowania przez chwilę).

### ID-FE-SES-03 – Revoke sesji (jeśli istnieje)
1. Jeśli na liście są aktywne sesje:
2. Kliknij **Revoke** przy wybranej sesji
3. Potwierdź w oknie dialogowym
4. **Oczekiwany:** Sesja znika z listy po zatwierdzeniu.

### ID-FE-SES-04 – Revoke – anulowanie
1. Kliknij **Revoke** przy sesji
2. W dialogu potwierdzenia kliknij **Cancel**
3. **Oczekiwany:** Sesja pozostaje na liście.

### ID-FE-SES-05 – Pusta lista
1. Jeśli wszystkie sesje zostały unieważnione:
2. Sprawdź, czy tabela pokazuje komunikat o braku aktywnych sesji
3. **Oczekiwany:** Stosowny komunikat (lub pusta tabela).

---

## 8. Diagnostics

### ID-FE-DIAG-01 – Wyświetlanie panelu diagnostycznego
1. Wybierz zakładkę **Diagnostics**
2. Sprawdź, czy widać:
   - Sekcję **RADIUS Test** – dropdown z profilami, pola username, password, calling station ID, przycisk Run
   - Sekcję **LDAP Test** – dropdown z profilami, pole username, przycisk Run
   - Sekcję **Result** – puste dopóki nie uruchomiono testu
3. **Oczekiwany:** Wszystkie elementy widoczne, dropdowny mają profile.

### ID-FE-DIAG-02 – Test RADIUS – pozytywny
1. W sekcji RADIUS:
   - Wybierz `default-radius` z dropdownu
   - **Username:** `user`
   - **Password:** `user123`
   - **Calling station ID:** _(puste lub `00-11-22-33-44-55`)_
2. Kliknij **Run**
3. **Oczekiwany:** Wynik pokazuje `kind: "accept"`, `username: "user"`, grupy (np. `admins` lub `users`), `sessionTtlSeconds`.

### ID-FE-DIAG-03 – Test RADIUS – złe hasło (Access-Reject)
1. To samo co ID-FE-DIAG-02, ale:
   - **Password:** `wrongpassword`
2. Kliknij **Run**
3. **Oczekiwany:** Wynik pokazuje `kind: "reject"` lub błąd.

### ID-FE-DIAG-04 – Test RADIUS – timeout (nieosiągalny serwer)
1. Wybierz profil RADIUS z nieosiągalnym hostem (np. wcześniej stworzony `test-radius` z hostem `10.0.0.1`)
2. Uruchom test
3. **Oczekiwany:** Wynik: timeout lub connection refused.

### ID-FE-DIAG-05 – Test LDAP – pozytywny
1. W sekcji LDAP:
   - Wybierz `default-ldap`
   - **Username:** `admin`
2. Kliknij **Run**
3. **Oczekiwany:** Wynik pokazuje `kind: "accept"`, `username`, grupy z LDAP (np. `admins`).

### ID-FE-DIAG-06 – Test LDAP – nieznany użytkownik
1. To samo, ale **Username:** `nieistniejacy123`
2. **Oczekiwany:** Wynik pokazuje błąd (użytkownik nie znaleziony / reject).

### ID-FE-DIAG-07 – Przełączanie między profilami w teście
1. Wybierz różne profile RADIUS z dropdownu
2. Sprawdź, czy formularz testu się nie resetuje przy zmianie
3. **Oczekiwany:** Pola username/password zostają, tylko profil się zmienia.

### ID-FE-DIAG-08 – Throttling testów (rate limit)
1. Uruchom test RADIUS 6 razy w ciągu minuty (limit: 5/min)
2. **Oczekiwany:** 6. request zwróci `429 Too many requests`.

### ID-FE-DIAG-09 – Test bez wybranego profilu
1. Jeśli dropdown RADIUS jest pusty (lub odznacz profil)
2. Kliknij **Run**
3. **Oczekiwany:** Przycisk nieaktywny lub informacja, że trzeba wybrać profil.

---

## Lista kontrolna – podsumowanie

| ID | Zakładka | Status |
|----|----------|--------|
| ID-FE-RAD-01 | RADIUS – lista | ☐ |
| ID-FE-RAD-02 | RADIUS – create | ☐ |
| ID-FE-RAD-03 | RADIUS – edit | ☐ |
| ID-FE-RAD-04 | RADIUS – walidacja: pusta nazwa | ☐ |
| ID-FE-RAD-05 | RADIUS – walidacja: duplikat | ☐ |
| ID-FE-RAD-06 | RADIUS – delete | ☐ |
| ID-FE-RAD-07 | RADIUS – delete in-use → 409 | ☐ |
| ID-FE-RAD-08 | RADIUS – cancel | ☐ |
| ID-FE-LDAP-01 | LDAP – lista | ☐ |
| ID-FE-LDAP-02 | LDAP – create | ☐ |
| ID-FE-LDAP-03 | LDAP – edit | ☐ |
| ID-FE-LDAP-04 | LDAP – walidacja | ☐ |
| ID-FE-LDAP-05 | LDAP – delete | ☐ |
| ID-FE-LDAP-06 | LDAP – cancel | ☐ |
| ID-FE-AUTH-01 | Auth – lista | ☐ |
| ID-FE-AUTH-02 | Auth – create (RADIUS) | ☐ |
| ID-FE-AUTH-03 | Auth – create (LDAP) | ☐ |
| ID-FE-AUTH-04 | Auth – create (local) | ☐ |
| ID-FE-AUTH-05 | Auth – create + role mappings | ☐ |
| ID-FE-AUTH-06 | Auth – edit | ☐ |
| ID-FE-AUTH-07 | Auth – walidacja: brak RADIUS | ☐ |
| ID-FE-AUTH-08 | Auth – walidacja: brak LDAP | ☐ |
| ID-FE-AUTH-09 | Auth – delete in-use (portal) → 409 | ☐ |
| ID-FE-AUTH-10 | Auth – delete in-use (admin) → 409 | ☐ |
| ID-FE-AUTH-11 | Auth – delete (nieużywany) | ☐ |
| ID-FE-AUTH-12 | Auth – sprzątanie | ☐ |
| ID-FE-PORT-01 | Portal – wyświetlanie | ☐ |
| ID-FE-PORT-02 | Portal – zmiana profilu | ☐ |
| ID-FE-PORT-03 | Portal – null | ☐ |
| ID-FE-PORT-04 | Portal – listener | ☐ |
| ID-FE-PORT-05 | Portal – listener disabled | ☐ |
| ID-FE-PORT-06 | Portal – login RADIUS + LDAP groups | ☐ |
| ID-FE-PORT-07 | Portal – login LDAP | ☐ |
| ID-FE-PORT-08 | Portal – guest session | ☐ |
| ID-FE-PORT-09 | Portal – login RADIUS radius_vsa | ☐ |
| ID-FE-PORT-10 | Portal – radius_vsa bez LDAP fallbacku | ☐ |
| ID-FE-ADM-01 | Admin – wyświetlanie | ☐ |
| ID-FE-ADM-02 | Admin – zmiana profilu | ☐ |
| ID-FE-ADM-03 | Admin – null | ☐ |
| ID-FE-ADM-04 | Admin – local odrzucony | ☐ |
| ID-FE-ADM-05 | Admin – login RADIUS | ☐ |
| ID-FE-ADM-06 | Admin – login LDAP | ☐ |
| ID-FE-ADM-07 | Admin – user bez roli admin | ☐ |
| ID-FE-ADM-08 | Admin – login RADIUS radius_vsa | ☐ |
| ID-FE-ADM-09 | Admin – radius_vsa bez LDAP mappingu | ☐ |
| ID-FE-ADM-10 | Admin – przywracanie | ☐ |
| ID-FE-SES-01 | Sessions – lista | ☐ |
| ID-FE-SES-02 | Sessions – refresh | ☐ |
| ID-FE-SES-03 | Sessions – revoke | ☐ |
| ID-FE-SES-04 | Sessions – revoke cancel | ☐ |
| ID-FE-SES-05 | Sessions – pusta lista | ☐ |
| ID-FE-DIAG-01 | Diagnostics – panel | ☐ |
| ID-FE-DIAG-02 | Diagnostics – RADIUS test OK | ☐ |
| ID-FE-DIAG-03 | Diagnostics – RADIUS reject | ☐ |
| ID-FE-DIAG-04 | Diagnostics – RADIUS timeout | ☐ |
| ID-FE-DIAG-05 | Diagnostics – LDAP test OK | ☐ |
| ID-FE-DIAG-06 | Diagnostics – LDAP not found | ☐ |
| ID-FE-DIAG-07 | Diagnostics – przełączanie profili | ☐ |
| ID-FE-DIAG-08 | Diagnostics – rate limit | ☐ |
| ID-FE-DIAG-09 | Diagnostics – brak profilu | ☐ |
