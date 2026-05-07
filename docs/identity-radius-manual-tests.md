# Manualne testy identity/RADIUS MVP

Zakres: weryfikacja implementacji identity/RADIUS bez uruchamiania skryptow testowych. Komendy sa celowo pojedynczymi krokami do wykonania recznie w VM-kach.

## Spis tresci

Legenda: 🖥️ = ma wariant konsola+przegladarka.

### Setup i topologia
- [Topologia i dane testowe](#topologia-i-dane-testowe) — IP, konta labowe, endpointy.
- [Przygotowanie](#przygotowanie) — status VM, logi, env, reset runtime, dostep do portalu z przegladarki (Firefox X11 lub SSH tunnel).

### A. Sanity check provideroow (ID-01..02)
- [ID-01](#id-01---ldap-i-radius-z-r1) — bezposredni `radtest` i `ldapsearch` z r1.
- [ID-02](#id-02---serwis-chroniony-na-h2) — endpoint HTTP na h2 dziala.

### B. Captive portal i sesje identity (ID-03..08)
- [ID-03](#id-03---pre-auth-gate-blokuje-h1---h2) 🖥️ — pre-auth gate blokuje h1→h2 bez sesji.
- [ID-04](#id-04---portal-jest-dostepny-a-status-sesji-jest-anonymous) 🖥️ — portal dostepny, sesja `authenticated:false`.
- [ID-05](#id-05---zle-haslo-nie-tworzy-sesji) 🖥️ — Access-Reject nie tworzy sesji.
- [ID-06](#id-06---poprawny-login-tworzy-sesje-i-pozwala-na-h1---h2) 🖥️ — login `user` tworzy sesje, firewall upsert, h1→h2 przechodzi.
- [ID-07](#id-07---body-nie-moze-nadpisac-sourceip) — `sourceIp` z polaczenia, nie z body (tylko konsola — browser nie wysyla niestandardowych pol).
- [ID-08](#id-08---logout-usuwa-sesje-i-znow-blokuje-h1---h2) 🖥️ — logout = revoke + blokada.

### C. Polityka, expiry, replay (ID-09..14)
- [ID-09](#id-09---guest-ma-sesje-ale-polityka-blokuje-grupe-guests) 🖥️ — `identity_group=guests` blokuje mimo udanego loginu.
- [ID-10](#id-10---wygasniecie-sesji-blokuje-nowy-ruch) 🖥️ — `expiresAt` blokuje nowy ruch bez restartu firewalla.
- [ID-11](#id-11---zmiana-grup-ldap-bez-reloginu) — refresher LDAP aktualizuje grupy bez reloginu.
- [ID-12](#id-12---timeout-radius-daje-czytelny-blad) — RADIUS timeout = `503` z czytelnym message.
- [ID-13](#id-13---replay-sesji-po-restarcie-backendu-i-firewalla) — replay sesji po restarcie backendu/firewalla.
- [ID-14](#id-14---loginlogout-nie-zmienia-config-snapshotow) — login/logout nie tyka config snapshotow.

### D. Regresja architektury (ID-15..16)
- [ID-15](#id-15---brak-hardcoded-h1h2-w-resolverze-stref) — resolver stref nie zalezy od labowych subnetow.
- [ID-16](#id-16---portal-listener-jako-konfiguracja-identity) — portal listener zapisuje sie w identity configu.

### E. Admin login przez RADIUS/LDAP (ID-17)
- [ID-17](#id-17---admin-login-przez-radius-z-mapowaniem-roli) — admin login + `adminRoleMappings`.

### F. Zarzadzanie profilami przez API (ID-18..24)
- [ID-18](#id-18---admin-token-z-lokalnego-loginu-helper-do-id-19) — helper: pobranie access tokenu.
- [ID-19](#id-19---radius-server-profile-crud-przez-api) + [ID-19a](#id-19a---radius-profile-test-endpoint) — RADIUS profile CRUD + `/test`.
- [ID-20](#id-20---ldap-server-profile-crud-i-test-endpoint) — LDAP profile CRUD + `/test`.
- [ID-21](#id-21---auth-profile-providerldap-ldap-only-portal) — auth profile `provider=ldap` (LDAP-only).
- [ID-22](#id-22---auth-profile-providerlocal-lokalny-user-przez-portal) — auth profile `provider=local` w portalu.
- [ID-23](#id-23---inactive-auth-profile-odrzuca-login) — `isActive:false` = misconfigured.
- [ID-24](#id-24---delete-profilu-w-uzyciu-zwraca-409) — delete in-use → `409`.

### G. Identity sessions admin + edge cases (ID-25..29)
- [ID-25](#id-25---identity-sessions-admin-api) — `/identity-sessions` list + revoke.
- [ID-26](#id-26---group-source-radius_vsa) — `groupSource:"radius_vsa"` pomija LDAP.
- [ID-27](#id-27---wiele-profili-admin-login--adminrolemappings) — switch `adminAuthenticationProfileId` zmienia role.
- [ID-28](#id-28---brak-admin-profile--blokada-zewnetrznego-admin-loginu) — admin pointer null = tylko lokalny break-glass.
- [ID-29](#id-29---sprzatanie-po-id-19id-28) — cleanup.

### H. Kryterium koncowe
- [Kryterium koncowe flow demo](#kryterium-koncowe-flow-demo) — checklist Issue 1-7 + rozszerzenie.

## Topologia i dane testowe

Lab:

- `h1`: `192.168.10.10`
- `r1`: `192.168.10.254`, `192.168.20.254`, `192.168.56.254`
- `h2`: `192.168.20.10`, chroniony HTTP na `:8080`
- `radius`: `192.168.20.30`, UDP `1812`, secret `radiussecret`
- `ldap`: `192.168.20.40`, base DN `dc=raptorgate,dc=local`
- portal captive: `https://192.168.10.254/portal/login`
- portal API z h1: `https://192.168.10.254/api/identity/*`
- backend lokalnie na r1: `https://127.0.0.1:3000/identity/*`

Konta:

| username | password | LDAP group |
| --- | --- | --- |
| `admin` | `admin1234` | `admins` |
| `user` | `user123` | `users` |
| `guest` | `guest123` | `guests` |

Przy logowaniu przez portal backend musi widziec `sourceIp=192.168.10.10`. Nie wysylamy `sourceIp` w body.

Komendy `vagrant` wykonuj z katalogu `vagrant/`. Do maszyn wchodzisz recznie przez `vagrant ssh h1`, `vagrant ssh r1`, `vagrant ssh h2`, `vagrant ssh radius` albo `vagrant ssh ldap`.

## Przygotowanie

1. Sprawdz, ze VM-ki stoja:

```bash
vagrant status
```

Po `vagrant destroy` albo po provisioningu samego `r1` nie zakladaj, ze providery auth i `h2` sa gotowe. Przed testami portalu upewnij sie, ze `r1`, `radius`, `ldap` i `h2` sa uruchomione i po zmianach reprovisionowane:

```bash
vagrant provision radius ldap h2 r1
```

Jezeli portal login zwraca `503` z message `ECONNREFUSED: connection refused, recv`, to nie jest blad UI ani captive portalu. To znaczy, ze `r1` nie moze polaczyc sie z RADIUS-em albo LDAP-em. Wroc wtedy do ID-01 i potwierdz `radtest` oraz `ldapsearch` zanim przejdziesz do testow przegladarkowych.

2. Na `r1` sprawdz podstawowe uslugi:

```bash
systemctl --no-pager --full status ngfw backend frontend
```

3. W osobnych terminalach na `r1` warto miec podglad logow:

```bash
sudo tail -f /var/log/raptorgate/backend/$(date +%F).log
```

```bash
sudo tail -f /var/log/raptorgate/firewall/$(date +%F).log
```

4. Sprawdz aktualna polityke firewalla na `r1`:

```bash
grep '^DEV_OVERRIDE_POLICY=' /etc/systemd/system/ngfw.env
```

Brak outputu jest OK i oznacza, ze `DEV_OVERRIDE_POLICY` nie jest ustawione. W tym labie to stan domyslny: NGFW dziala z normalna polityka, a nie z override z env.

Uwaga: jezeli `DEV_OVERRIDE_POLICY` jest allow-all, testy blokowania po braku sesji/logout/expire nie zweryfikuja enforcementu identity. Wtedy problem jest w sposobie spiecia identity z normalna polityka/configiem, a nie w RADIUS.

To samo dotyczy aktywnego config snapshotu. Seedowe `vagrant/configs/policies.json` zawiera identity-aware przyklady dla `auth_state`, `identity_group` i portow aplikacyjnych, ale bez sensownych `zone_interfaces` testy wielu polityk per strefa nie potwierdza live evaluatora. Przed ID-03/06/08/09/10/11/13 aktywny config musi byc identity-aware i nie moze byc globalnym allow-all.

Sprawdz tez pozostale zmienne:

```text
DEV_MODE=true
SSL_INSPECTION_ENABLED=true
TLS_REDIRECT_EXCLUDED_DESTINATIONS=192.168.10.254:443
```

Potem zrestartuj firewall:

```bash
sudo systemctl restart ngfw
```

5. Reset stanu runtime przed wybranym testem, jezeli chcesz zaczac od pustych sesji:

```bash
sudo systemctl restart ngfw
sudo systemctl restart backend
```

Limit throttlingu loginu to 5 prob na 60 sekund dla jednego klienta. Jesli zobaczysz `429`, odczekaj minute albo zrestartuj backend przed dalszymi probami.

6. Dostep do portalu z przegladarki:

Portal `https://192.168.10.254/portal/login` jest na interfejsie `eth1` r1. Domyslny browser hosta zwykle potrafi wejsc na portal bez tunelu, ale wtedy backend widzi `sourceIp` bridge'a hosta, np. `192.168.10.1`. To testuje tylko render portalu.

Do testow identity + enforcementu h1 -> h2 z GUI uzyj tunelu SOCKS przez `h1` i PAC w Firefoxie. Wtedy portal i h2 ida przez `h1`, a backend widzi klienta jako `sourceIp=192.168.10.10`.

Uwaga: nie ustawiaj manualnego SOCKS dla calego Firefoxa. Firefox/Chrome moga wysylac przez proxy poboczne polaczenia, ktore zapychaja tunel i portal zaczyna ladowac sie w nieskonczonosc. PAC ponizej kieruje przez SOCKS tylko dwa labowe IP, reszta idzie direct.

**Opcja C — Firefox na hoscie przez SOCKS + PAC (ZALECANE dla GUI)**

Po `vagrant destroy`, restarcie hosta albo ponownym deployu wykonaj od nowa:

```bash
cd /home/dawid/Project/RaptorGate/vagrant
vagrant status h1 r1 h2
vagrant ssh-config h1 > /tmp/h1-portal.ssh
ssh -F /tmp/h1-portal.ssh -o ExitOnForwardFailure=yes -M -S /tmp/h1-portal-socks.ctl -f -N -D 127.0.0.1:1090 h1
```

Jezeli port `1090` jest zajety albo poprzedni tunnel zawisl:

```bash
ssh -F /tmp/h1-portal.ssh -S /tmp/h1-portal-socks.ctl -O exit h1 2>/dev/null || true
ss -ltnp 'sport = :1090'
```

Jezeli `ss` nadal pokazuje stary proces `ssh` na `127.0.0.1:1090`, zamknij ten konkretny PID i uruchom tunnel jeszcze raz:

```bash
kill <PID_Z_SS>
ssh -F /tmp/h1-portal.ssh -o ExitOnForwardFailure=yes -M -S /tmp/h1-portal-socks.ctl -f -N -D 127.0.0.1:1090 h1
```

Zweryfikuj tunnel z hosta przed otwarciem Firefoxa:

```bash
curl -k -sS --connect-timeout 3 -m 6 --socks5-hostname 127.0.0.1:1090 https://192.168.10.254/api/identity/session
```

Oczekiwane:

```json
{"statusCode":200,"message":"Identity session status","data":{"authenticated":false,"sourceIp":"192.168.10.10"}}
```

Sprawdz tez sam HTML portalu:

```bash
curl -k -sS -I --connect-timeout 3 -m 6 --socks5-hostname 127.0.0.1:1090 https://192.168.10.254/portal/login
```

Oczekiwane: `HTTP/1.1 200 OK`.

Przed loginem ruch do h2 ma byc blokowany:

```bash
curl -sS -i --connect-timeout 3 -m 6 --socks5-hostname 127.0.0.1:1090 http://192.168.20.10:8080/api/ping
```

Oczekiwane: timeout.

W Firefoxie utworz osobny profil testowy i ustaw:

- `Settings -> Network Settings`
- `Automatic proxy configuration URL`
- URL PAC:

```text
data:application/x-ns-proxy-autoconfig,function FindProxyForURL(url,host){if(host=="192.168.10.254"||host=="192.168.20.10")return "SOCKS5 127.0.0.1:1090";return "DIRECT";}
```

Kliknij `Reload` przy PAC, potem `OK`.

Test w Firefoxie:

1. `https://192.168.10.254/api/identity/session` -> JSON z `sourceIp:"192.168.10.10"`.
2. `https://192.168.10.254/portal/login` -> "Advanced" -> "Accept Risk" -> login `user/user123`.
3. Nowa zakladka: `http://192.168.20.10:8080/api/ping` -> JSON `{"status":"ok"}`.
4. Logout w portalu -> ten sam URL do h2 -> timeout.

Po testach zamknij tunnel:

```bash
ssh -F /tmp/h1-portal.ssh -S /tmp/h1-portal-socks.ctl -O exit h1
```

Jezeli Firefox znow zacznie ladowac portal w nieskonczonosc:

1. Zamknij okno Firefoxa z profilem testowym.
2. Zamknij tunnel komenda `ssh -O exit` powyzej.
3. Sprawdz `ss -ltnp 'sport = :1090'`; jezeli zostal proces `ssh`, zamknij jego PID.
4. Uruchom tunnel od nowa i najpierw potwierdz `curl ... /api/identity/session`.

**Opcja D — host route przez h1 (alternatywa bez proxy, wymaga sudo na hoscie)**

Ten wariant zapisuje sesje dla IP bridge'a hosta, np. `192.168.10.1`, a nie dla `192.168.10.10`. Uzywaj go tylko jezeli chcesz testowac domyslny browser hosta bez PAC.

Najpierw sprawdz aktualne trasy, bo nazwy `virbrX` zaleza od libvirt:

```bash
ip route get 192.168.10.254
ip route get 192.168.20.10
```

Na hoscie przekieruj ruch do h2 przez h1:

```bash
sudo ip route replace 192.168.20.0/24 via 192.168.10.10
```

Na h1 wlacz forwarding:

```bash
vagrant ssh h1 -- 'sudo sysctl -w net.ipv4.ip_forward=1'
```

Po tescie przywroc route do bridge'a z `ip route get 192.168.20.10` i wylacz forwarding, np.:

```bash
sudo ip route replace 192.168.20.0/24 dev virbr3
vagrant ssh h1 -- 'sudo sysctl -w net.ipv4.ip_forward=0'
```

Weryfikacja zrodla na r1:

```bash
sudo tcpdump -ni any 'host 192.168.20.10 and port 8080'
```

Pusto = pakiety nie ida przez r1, wiec test nic nie sprawdza.

**Opcja A — Firefox na h1 przez SSH X11 (alternatywa)**: jezeli chcesz zeby `sourceIp` byl scisle `192.168.10.10` bez SOCKS, zainstaluj Firefoxa na h1 i przekieruj X11. `vagrant ssh h1 -- -X`, w sesji `sudo apt-get install -y firefox-esr xauth` (raz), `firefox https://192.168.10.254/portal/login &`. Wolniejszy render, wymaga GUI biblioteki na h1.

## ID-01 - LDAP i RADIUS z r1

Cel: potwierdzic scenariusz `r1 -> RADIUS -> LDAP` i konta labowe.

Na `r1`:

```bash
ldapsearch -x -H ldap://192.168.20.40 -b dc=raptorgate,dc=local '(uid=admin)' uid
ldapsearch -x -H ldap://192.168.20.40 -b dc=raptorgate,dc=local '(uid=user)' uid
ldapsearch -x -H ldap://192.168.20.40 -b dc=raptorgate,dc=local '(uid=guest)' uid
```

Oczekiwane: kazde zapytanie zwraca odpowiedni `uid`.

Na `r1`:

```bash
radtest admin admin1234 192.168.20.30 0 radiussecret
radtest user user123 192.168.20.30 0 radiussecret
radtest guest guest123 192.168.20.30 0 radiussecret
```

Oczekiwane: `Access-Accept`.

Na `r1`:

```bash
radtest admin wrong-password 192.168.20.30 0 radiussecret
```

Oczekiwane: `Access-Reject`.

## ID-02 - Serwis chroniony na h2

Cel: potwierdzic, ze h2 ma dzialajacy endpoint.

Na `h2`:

```bash
systemctl --no-pager --full status h2-http
curl -fsS http://127.0.0.1:8080/api/ping
curl -fsS http://127.0.0.1:8080/api/whoami
```

Oczekiwane:

- `/api/ping` zwraca `{"status":"ok"}`
- `/api/whoami` zwraca `{"service":"h2-http","resource":"protected"}`

## ID-03 - Pre-auth gate blokuje h1 -> h2

Cel: bez sesji identity ruch z h1 do h2 nie moze przejsc.

Najpierw zresetuj runtime state na `r1`:

```bash
sudo systemctl restart ngfw
sudo systemctl restart backend
```

### Konsola (curl)

Na `h1`:

```bash
curl --connect-timeout 3 -m 5 -i http://192.168.20.10:8080/api/ping
```

Oczekiwane: timeout albo brak odpowiedzi HTTP 200.

Na `r1` w logu firewalla:

```bash
sudo grep -E 'policy.packet.dropped|policy_eval' /var/log/raptorgate/firewall/$(date +%F).log
```

Oczekiwane: wpis drop z `src_ip=192.168.10.10`, `dst_ip=192.168.20.10`, `dst_port=8080`.

### Przegladarka

W Firefoxie (Opcja C albo A z Przygotowania) wpisz `http://192.168.20.10:8080/api/ping`.

Oczekiwane: strona sie nie laduje, browser pokazuje timeout / "Unable to connect". Log firewalla na `r1` ma drop jak wyzej.

## ID-04 - Portal jest dostepny, a status sesji jest anonymous

Cel: portal ma byc dostepny z h1 mimo pre-auth gate.

### Konsola (curl)

Na `h1`:

```bash
curl -k -i https://192.168.10.254/
```

Oczekiwane: `302` do `/portal/login`.

Na `h1`:

```bash
curl -k -sS https://192.168.10.254/api/identity/session
```

Oczekiwane: envelope z `data.authenticated:false` i `data.sourceIp:"192.168.10.10"`.

### Przegladarka

W Firefoxie wejdz na `https://192.168.10.254/`. Zaakceptuj self-signed cert.

Oczekiwane:

- redirect do `/portal/login`
- strona portalu ladnie sie renderuje (formularz username/password)
- naglowek strony pokazuje stan `anonymous` lub komunikat typu "Please sign in"
- DevTools (F12) → Network → request `/api/identity/session` zwraca `200` z `data.authenticated:false`

## ID-05 - Zle haslo nie tworzy sesji

Cel: Access-Reject z RADIUS nie tworzy sesji backendu ani firewalla.

### Konsola (curl)

Na `h1`:

```bash
curl -k -sS -i -X POST https://192.168.10.254/api/identity/login -H 'content-type: application/json' -d '{"username":"user","password":"wrong-password"}'
```

Oczekiwane:

- HTTP `401`
- odpowiedz ma envelope bledu z `statusCode:401`, `error:"Unauthorized"` i `message:"Invalid username or password."`

Na `h1`:

```bash
curl -k -sS https://192.168.10.254/api/identity/session
```

Oczekiwane: nadal `data.authenticated:false`.

Na `r1` w logu backendu:

```bash
sudo grep -E 'auth.radius.access_reject|identity.session.rejected|identity.session.created' /var/log/raptorgate/backend/$(date +%F).log
```

Oczekiwane:

- jest `auth.radius.access_reject`
- jest `identity.session.rejected`
- nie ma nowego `identity.session.created` dla tej proby

### Przegladarka

W Firefoxie na `https://192.168.10.254/portal/login`:

1. Wpisz `user` / `wrong-password`.
2. Kliknij "Sign in".

Oczekiwane:

- formularz pokazuje komunikat bledu (np. "Invalid username or password" / status `rejected`)
- strona zostaje na `/portal/login`, nie ma przekierowania do "authenticated" widoku
- DevTools → Network → POST `/api/identity/login` zwraca `401` z envelopem bledu
- log backendu ma `auth.radius.access_reject` i `identity.session.rejected`

## ID-06 - Poprawny login tworzy sesje i pozwala na h1 -> h2

Cel: backend wykonuje RADIUS auth, pobiera grupy z LDAP, tworzy sesje i synchronizuje firewall.

### Konsola (curl)

Na `h1`:

```bash
curl -k -sS -i -X POST https://192.168.10.254/api/identity/login -H 'content-type: application/json' -d '{"username":"user","password":"user123"}'
```

Oczekiwane:

- HTTP `201`
- body jest envelopem, a `data` ma `sessionId`, `username:"user"`, `sourceIp:"192.168.10.10"`, `authenticatedAt`, `expiresAt`

Na `h1`:

```bash
curl -k -sS https://192.168.10.254/api/identity/session
```

Oczekiwane:

- `data.authenticated:true`
- `data.username:"user"`
- `data.groups` zawiera `users`

Na `r1` w logu backendu:

```bash
sudo grep -E 'auth.radius.access_accept|identity.ldap.lookup|identity.groups.resolved|identity.session.created' /var/log/raptorgate/backend/$(date +%F).log
```

Oczekiwane: sa wpisy `access_accept`, `identity.groups.resolved` i `identity.session.created`.

Na `r1` w logu firewalla:

```bash
sudo grep -E 'identity.session.upsert' /var/log/raptorgate/firewall/$(date +%F).log
```

Oczekiwane: wpis `identity.session.upsert` dla `client_ip=192.168.10.10`, `username=user`.

Na `h1`:

```bash
curl -fsS http://192.168.20.10:8080/api/ping
```

Oczekiwane: `{"status":"ok"}`.

### Przegladarka

W Firefoxie na `https://192.168.10.254/portal/login`:

1. Wpisz `user` / `user123`.
2. Kliknij "Sign in".

Oczekiwane:

- portal przelacza sie w widok "authenticated" pokazujac `username:user`, grupy, `expiresAt`
- DevTools → Network → POST `/api/identity/login` zwraca `201`
- GET `/api/identity/session` (po refresh) zwraca `data.authenticated:true`, `groups` zawiera `users`

Test ruchu do h2 z przegladarki:

3. W nowej zakladce wejdz na `http://192.168.20.10:8080/api/ping`.

Oczekiwane: strona pokazuje JSON `{"status":"ok"}`. Logi `r1` jak w wariancie konsolowym.

## ID-07 - Body nie moze nadpisac sourceIp

Cel: `sourceIp` pochodzi z polaczenia/proxy, nie z request body.

Na `h1`:

```bash
curl -k -sS -i -X POST https://192.168.10.254/api/identity/login -H 'content-type: application/json' -d '{"username":"user","password":"user123","sourceIp":"192.168.20.10"}'
```

Oczekiwane w obecnym DTO: HTTP `400` z envelope bledu walidacji dodatkowego pola. Akceptowalny wariant po przyszlej zmianie DTO: login przechodzi, ale `data.sourceIp` w odpowiedzi nadal jest `192.168.10.10`. Nieakceptowalne: sesja dla IP z body.

## ID-08 - Logout usuwa sesje i znow blokuje h1 -> h2

Cel: logout usuwa sesje w backendzie i wysyla revoke do firewalla.

Warunek startowy: aktywna sesja `user` z ID-06.

### Konsola (curl)

Na `h1`:

```bash
curl -k -sS -i -X POST https://192.168.10.254/api/identity/logout
```

Oczekiwane:

- HTTP `200`
- body ma `data.removed:true`

Na `h1`:

```bash
curl -k -sS https://192.168.10.254/api/identity/session
```

Oczekiwane: `data.authenticated:false`.

Na `r1`:

```bash
sudo grep -E 'identity.session.revoked' /var/log/raptorgate/backend/$(date +%F).log
sudo grep -E 'identity.session.revoke' /var/log/raptorgate/firewall/$(date +%F).log
```

Oczekiwane: backend loguje revoke, firewall loguje `removed=true`.

Na `h1`:

```bash
curl --connect-timeout 3 -m 5 -i http://192.168.20.10:8080/api/ping
```

Oczekiwane: timeout albo brak HTTP 200.

### Przegladarka

Z aktywna sesja z ID-06 (browser):

1. Na portalu kliknij "Sign out" / "Logout".

Oczekiwane:

- portal wraca do widoku anonymous, formularz login znow widoczny
- DevTools → Network → POST `/api/identity/logout` zwraca `200`, `data.removed:true`
- GET `/api/identity/session` zwraca `data.authenticated:false`

2. W nowej zakladce wejdz `http://192.168.20.10:8080/api/ping`.

Oczekiwane: timeout / connection failed. Logi `r1` maja revoke.

## ID-09 - Guest ma sesje, ale polityka blokuje grupe guests

Cel: `identity_group` w RaptorLang blokuje `guests`, mimo poprawnego RADIUS loginu.

Najpierw wyloguj ewentualna sesje:

```bash
curl -k -sS -X POST https://192.168.10.254/api/identity/logout
```

### Konsola (curl)

Na `h1`:

```bash
curl -k -sS -i -X POST https://192.168.10.254/api/identity/login -H 'content-type: application/json' -d '{"username":"guest","password":"guest123"}'
```

Oczekiwane: HTTP `201`.

Na `h1`:

```bash
curl -k -sS https://192.168.10.254/api/identity/session
```

Oczekiwane: `data.authenticated:true`, `data.username:"guest"`, `data.groups` zawiera `guests`.

Na `h1`:

```bash
curl --connect-timeout 3 -m 5 -i http://192.168.20.10:8080/api/ping
```

Oczekiwane: timeout albo brak HTTP 200.

Na `r1` w logu firewalla:

```bash
sudo grep -E 'policy.packet.dropped|policy_eval' /var/log/raptorgate/firewall/$(date +%F).log
```

Oczekiwane: drop dla `src_ip=192.168.10.10`, `dst_port=8080`.

### Przegladarka

W Firefoxie na `https://192.168.10.254/portal/login`:

1. Wpisz `guest` / `guest123`, kliknij "Sign in".

Oczekiwane:

- portal pokazuje widok authenticated z `username:guest`, `groups` zawiera `guests`
- POST `/api/identity/login` zwrocil `201`

2. W nowej zakladce wejdz `http://192.168.20.10:8080/api/ping`.

Oczekiwane: strona sie nie laduje, browser pokazuje timeout / "Unable to connect" mimo aktywnej sesji. Logi firewalla na `r1` maja drop dla `dst_port=8080`. Polityka blokuje grupe `guests`.

## ID-10 - Wygasniecie sesji blokuje nowy ruch

Cel: `expiresAt` dziala w backendzie i firewallu bez restartu firewalla.

Zeby nie czekac 30 minut, ustaw tymczasowo krotki TTL backendu:

```bash
sudo systemctl edit backend
```

Wklej override:

```ini
[Service]
Environment=IDENTITY_SESSION_TTL_SECONDS=20
Environment=IDENTITY_SESSION_SWEEP_INTERVAL_MS=5000
Environment=IDENTITY_SESSION_REPLAY_INTERVAL_MS=5000
```

Potem:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ngfw
sudo systemctl restart backend
```

### Konsola (curl)

Na `h1` zaloguj `user`:

```bash
curl -k -sS -i -X POST https://192.168.10.254/api/identity/login -H 'content-type: application/json' -d '{"username":"user","password":"user123"}'
curl -fsS http://192.168.20.10:8080/api/ping
```

Oczekiwane: login `201`, ping HTTP zwraca `{"status":"ok"}`.

Odczekaj minimum 25-30 sekund. Potem na `h1`:

```bash
curl -k -sS https://192.168.10.254/api/identity/session
curl --connect-timeout 3 -m 5 -i http://192.168.20.10:8080/api/ping
```

Oczekiwane:

- status sesji: `data.authenticated:false`
- nowy ruch do h2: timeout albo brak HTTP 200

Na `r1`:

```bash
sudo grep -E 'identity.session.expired|identity.session.revoke|policy.packet.dropped' /var/log/raptorgate/backend/$(date +%F).log /var/log/raptorgate/firewall/$(date +%F).log
```

Oczekiwane: backend loguje `identity.session.expired`, firewall dostaje revoke albo przynajmniej nowy pakiet po `expiresAt` jest dropowany.

### Przegladarka

W Firefoxie na `https://192.168.10.254/portal/login`:

1. Zaloguj `user/user123`. W innej zakladce sprawdz `http://192.168.20.10:8080/api/ping` — zwraca `{"status":"ok"}`.
2. Zostaw zakladke portalu otwarta. PortalPage ma timer ktory po `expiresAt` przelaczy widok na `anonymous` z reason `expired` (patrz `frontend/src/pages/PortalPage.tsx`).
3. Odczekaj 25-30 sekund.

Oczekiwane:

- portal sam przeskakuje do widoku anonymous z banerem typu "Session expired"
- refresh zakladki h2 (`http://192.168.20.10:8080/api/ping`) — timeout / connection failed
- DevTools → Network → GET `/api/identity/session` po wygaśnięciu zwraca `data.authenticated:false`

Po tescie usun override:

```bash
sudo systemctl revert backend
sudo systemctl restart ngfw
sudo systemctl restart backend
```

## ID-11 - Zmiana grup LDAP bez reloginu

Cel: grupy uzytkownika sa modelem niezaleznym od lifecycle sesji; refresher aktualizuje firewall przez Upsert.

Warunek: `IDENTITY_GROUP_REFRESH_INTERVAL_MS` jest wieksze niz `0` (domyslnie `60000`).

1. Na `h1` zaloguj `user` i potwierdz, ze h2 dziala:

```bash
curl -k -sS -i -X POST https://192.168.10.254/api/identity/login -H 'content-type: application/json' -d '{"username":"user","password":"user123"}'
curl -fsS http://192.168.20.10:8080/api/ping
```

2. Na `ldap` uruchom interaktywnie:

```bash
ldapmodify -x -D "cn=admin,dc=raptorgate,dc=local" -w admin
```

Wklej i zakoncz `Ctrl-D`:

```ldif
dn: cn=guests,ou=groups,dc=raptorgate,dc=local
changetype: modify
add: memberUid
memberUid: user
```

3. Odczekaj ponad `IDENTITY_GROUP_REFRESH_INTERVAL_MS` (domyslnie ok. 70 sekund). Na `r1`:

```bash
sudo grep -E 'identity.groups.refreshed|identity.session.replayed|identity.session.upsert' /var/log/raptorgate/backend/$(date +%F).log /var/log/raptorgate/firewall/$(date +%F).log
```

Oczekiwane: przy faktycznej zmianie grup backend loguje `identity.groups.refreshed`, a firewall dostaje kolejny `identity.session.upsert`. Jezeli widzisz tylko `identity.session.replayed`, zmiana grup nie zostala jeszcze zaciagnieta.

4. Na `h1` bez ponownego logowania:

```bash
curl --connect-timeout 3 -m 5 -i http://192.168.20.10:8080/api/ping
```

Oczekiwane: ruch jest zablokowany, bo `user` stal sie czlonkiem `guests`.

5. Sprzatanie na `ldap`:

```bash
ldapmodify -x -D "cn=admin,dc=raptorgate,dc=local" -w admin
```

Wklej i zakoncz `Ctrl-D`:

```ldif
dn: cn=guests,ou=groups,dc=raptorgate,dc=local
changetype: modify
delete: memberUid
memberUid: user
```

## ID-12 - Timeout RADIUS daje czytelny blad

Cel: backend rozroznia Access-Reject od niedostepnego RADIUS-a.

Na `radius`:

```bash
sudo systemctl stop freeradius
```

Na `h1`:

```bash
curl -k -sS -i -X POST https://192.168.10.254/api/identity/login -H 'content-type: application/json' -d '{"username":"user","password":"user123"}'
```

Oczekiwane:

- HTTP `503`
- odpowiedz ma envelope bledu z `statusCode:503`, `error:"Service Unavailable"` i `message` zawiera `RADIUS timeout` albo `RADIUS error`
- `GET /api/identity/session` nadal pokazuje `data.authenticated:false`

Na `r1`:

```bash
sudo grep -E 'auth.radius.timeout|auth.radius.error|http.request.failed' /var/log/raptorgate/backend/$(date +%F).log
```

Oczekiwane: log timeout/error bez `identity.session.created`.

Na `radius` przywroc usluge:

```bash
sudo systemctl start freeradius
```

## ID-13 - Replay sesji po restarcie backendu i firewalla

Cel: backend odtwarza aktywne sesje z runtime store i replayuje je do firewalla bez ponownego logowania uzytkownika.

Warunek: aktywna sesja `user` z ID-06 i `IDENTITY_SESSION_REPLAY_INTERVAL_MS` jest wieksze niz `0` (domyslnie `30000`).

1. Na `h1` potwierdz aktywna sesje i dostep do h2:

```bash
curl -k -sS https://192.168.10.254/api/identity/session
curl -fsS http://192.168.20.10:8080/api/ping
```

Oczekiwane: `data.authenticated:true` i ping zwraca `{"status":"ok"}`.

2. Na `r1` sprawdz, ze backendowy runtime store zawiera sesje:

```bash
sudo grep -R "192.168.10.10" /resources/backend/data/json-db/identity_sessions.json
```

Oczekiwane: wpis sesji dla `192.168.10.10`.

3. Na `r1` zrestartuj backend:

```bash
sudo systemctl restart backend
```

4. Na `h1` bez ponownego logowania:

```bash
curl -k -sS https://192.168.10.254/api/identity/session
```

Oczekiwane: `data.authenticated:true`, bo backend odtworzyl sesje z `identity_sessions.json`.

5. Na `r1` zrestartuj firewall:

```bash
sudo systemctl restart ngfw
```

6. Odczekaj ponad `IDENTITY_SESSION_REPLAY_INTERVAL_MS` i sprawdz logi na `r1`:

```bash
sudo grep -E 'firewall.identity_session.replay.succeeded|identity.session.upsert' /var/log/raptorgate/backend/$(date +%F).log /var/log/raptorgate/firewall/$(date +%F).log
```

Oczekiwane: backend loguje `firewall.identity_session.replay.succeeded`, a firewall dostaje swiezy `identity.session.upsert` dla `client_ip=192.168.10.10`.

7. Na `h1` bez ponownego logowania:

```bash
curl -fsS http://192.168.20.10:8080/api/ping
```

Oczekiwane: po cyklu replay ruch znow przechodzi. To nie jest zalezne od refreshu grup.

## ID-14 - Login/logout nie zmienia config snapshotow

Cel: aktywne sesje identity sa runtime state, nie config snapshot.

Na `r1` przed loginem:

```bash
stat -c '%Y %n' /resources/ngfw/app_config.json /resources/ngfw/policies.json /resources/backend/data/json-db/configuration_snapshots.json
```

Na `h1` wykonaj login i logout:

```bash
curl -k -sS -i -X POST https://192.168.10.254/api/identity/login -H 'content-type: application/json' -d '{"username":"user","password":"user123"}'
curl -k -sS -i -X POST https://192.168.10.254/api/identity/logout
```

Na `r1` ponownie:

```bash
stat -c '%Y %n' /resources/ngfw/app_config.json /resources/ngfw/policies.json /resources/backend/data/json-db/configuration_snapshots.json
grep -R "192.168.10.10" /resources/ngfw/app_config.json /resources/ngfw/policies.json /resources/backend/data/json-db/configuration_snapshots.json
```

Oczekiwane:

- timestampy configow i snapshotow nie zmieniaja sie przez login/logout
- `grep` nie znajduje `192.168.10.10` ani `sessionId` w config snapshotach
- `data/json-db/identity_sessions.json` moze sie zmienic, bo to runtime store aktywnych sesji, nie config snapshot
- logi backend/firewall pokazuja runtime events `identity.session.created`, `identity.session.upsert`, `identity.session.revoked`, `identity.session.revoke`

## ID-15 - Brak hardcoded h1/h2 w resolverze stref

Cel: potwierdzic regresyjnie, ze data plane nie wybiera stref po `192.168.10.0/24`, `192.168.20.0/24`, `eth1`, `eth2` zaszytych w kodzie.

Na hoście developerskim:

```bash
cargo test -p ngfw routing -- --nocapture
cargo test -p ngfw policy_eval_uses_configured_non_lab_zone_interfaces -- --nocapture
```

Oczekiwane: przechodzi test routingu dla subnetow `10.77.10.0/24` i `10.88.20.0/24`. Jesli test pada komunikatem o braku egress interface albo zone pair, wrocil hardcoded labowy mapping.

## ID-16 - Portal listener jako konfiguracja identity

Cel: admin widzi i zapisuje intencje deploymentu portalu bez edycji env.

Uwaga: w tym etapie `portalListener` jest control-plane configiem. Labowy nginx dalej uzywa statycznego vhosta, a generowanie runtime listenera jest zakresem Issue J.

W panelu admina:

1. Otworz `Identity -> Portal Settings`.
2. Ustaw authentication profile portalu.
3. Wypelnij listener: interface, zone ID, bind address i bind port.
4. Zapisz ustawienia.

Na `r1` sprawdz persistent config backendu:

```bash
sudo jq '.settings.portalListener' /resources/backend/data/json-db/identity-config.json
```

Oczekiwane: `portalListener` ma zapisane pola `enabled`, `interfaceName`, `zoneId`, `bindAddress`, `bindPort`.

Uwaga: ten test nie wymaga dynamicznego generowania nginx. MVP zapisuje konfiguracje portalu jako czesc identity configu, a labowy vhost nginx nadal jest zarzadzany deploymentem.

## ID-17 - Admin login przez RADIUS z mapowaniem roli

Cel: admin zewnetrzny dostaje role tylko przez jawne `adminRoleMappings`.

Warunek: aktywny `adminAuthenticationProfileId` wskazuje profil RADIUS, a profil ma mapping:

```json
{
  "matchType": "ldap_group",
  "matchValue": "admins",
  "role": "admin"
}
```

Na `r1`:

```bash
curl -k -sS -i -X POST https://127.0.0.1:3000/auth/login -H 'content-type: application/json' -d '{"username":"admin","password":"admin1234"}'
```

Oczekiwane:

- HTTP `201`
- odpowiedz zawiera `roles:["admin"]`, `authProvider:"radius"` i access token
- refresh token jest ustawiony jako cookie

Sprawdz endpoint wymagajacy uprawnienia do odczytu konfiguracji identity:

```bash
TOKEN='<access token z odpowiedzi>'
curl -k -sS -i https://127.0.0.1:3000/identity-config -H "authorization: Bearer $TOKEN"
```

Oczekiwane: endpoint przepuszcza zgodnie z rola `admin` i jej permisjami.

Usun lub zmien mapping tak, zeby grupa `admins` nie pasowala, i powtorz login:

```bash
curl -k -sS -i -X POST https://127.0.0.1:3000/auth/login -H 'content-type: application/json' -d '{"username":"admin","password":"admin1234"}'
```

Oczekiwane:

- login zewnetrzny jest odrzucony
- backend loguje `auth.admin.authorization_denied`
- lokalny break-glass admin nadal moze zalogowac sie lokalnym haslem, nawet gdy RADIUS jest niedostepny

## ID-18 - Admin token z lokalnego loginu (helper do ID-19+)

Cel: zdobyc access token dla endpointow `/identity-config` i `/identity-sessions`. Domyslny lokalny admin: `admin/admin`.

Na `r1`:

```bash
ACCESS_TOKEN=$(curl -k -sS -X POST https://127.0.0.1:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"admin"}' | jq -r '.data.accessToken')
echo "$ACCESS_TOKEN" | head -c 20
```

Oczekiwane: token niepusty. Jezeli haslo lokalnego admina jest inne, podmien w body.

Sprawdz, ze widzisz aktualny config:

```bash
curl -k -sS https://127.0.0.1:3000/identity-config -H "authorization: Bearer $ACCESS_TOKEN" | jq '.data | {radius:[.radiusServerProfiles[].id], ldap:[.ldapServerProfiles[].id], auth:[.authenticationProfiles[].id], settings:.settings}'
```

Oczekiwane: lista zawiera `default-radius`, `default-ldap` (jesli LDAP enabled), `default-portal-radius`, a `settings.portalAuthenticationProfileId` to `default-portal-radius`.

## ID-19 - RADIUS server profile CRUD przez API

Cel: admin moze tworzyc, aktualizowac i usuwac profile RADIUS, secrety idą przez `secret://` ref.

Najpierw wgraj nowy secret (re-uzywamy istniejacego, jesli juz w secret store - inaczej upsert):

```bash
curl -k -sS -X PUT 'https://127.0.0.1:3000/secrets/identity/radius/lab-secondary' \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"value":"radiussecret"}'
```

Oczekiwane: `201`, body z metadata bez wartosci.

Stworz drugi RADIUS server profile:

```bash
RADIUS_ID=$(curl -k -sS -X POST https://127.0.0.1:3000/identity-config/radius-profiles \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"Lab secondary RADIUS",
    "description":"Test profile",
    "isActive":true,
    "host":"192.168.20.30",
    "port":1812,
    "sharedSecretRef":"secret://identity/radius/lab-secondary",
    "timeoutMs":3000,
    "retries":1,
    "nasIp":"192.168.20.254",
    "nasIdentifier":"raptorgate-r1",
    "calledStationId":null
  }' | jq -r '.data.radiusServerProfiles[] | select(.name=="Lab secondary RADIUS") | .id')
echo "$RADIUS_ID"
```

Oczekiwane: niepuste UUID.

Update profile (zmiana retries):

```bash
curl -k -sS -X PUT "https://127.0.0.1:3000/identity-config/radius-profiles/$RADIUS_ID" \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"Lab secondary RADIUS",
    "description":"Updated",
    "isActive":true,
    "host":"192.168.20.30",
    "port":1812,
    "sharedSecretRef":"secret://identity/radius/lab-secondary",
    "timeoutMs":3000,
    "retries":2,
    "nasIp":"192.168.20.254",
    "nasIdentifier":"raptorgate-r1",
    "calledStationId":null
  }' | jq '.data.radiusServerProfiles[] | select(.id==env.RADIUS_ID) | .retries'
```

Oczekiwane: `2`.

Delete dziala dopiero po teście ID-19a. Najpierw przejdz dalej.

## ID-19a - RADIUS profile test endpoint

Cel: `/identity-config/radius-profiles/:id/test` zwraca diagnostyke bez tworzenia sesji.

Access-Accept:

```bash
curl -k -sS -X POST "https://127.0.0.1:3000/identity-config/radius-profiles/$RADIUS_ID/test" \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"username":"user","password":"user123"}' | jq
```

Oczekiwane: `data.outcome:"accept"`, brak `password` w odpowiedzi, brak nowej sesji w `/identity/session`.

Access-Reject:

```bash
curl -k -sS -X POST "https://127.0.0.1:3000/identity-config/radius-profiles/$RADIUS_ID/test" \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"username":"user","password":"wrong"}' | jq
```

Oczekiwane: `data.outcome:"reject"`.

Test wlacza throttle 5/60s — po 5 probach `429`.

## ID-20 - LDAP server profile CRUD i test endpoint

Cel: analogicznie do ID-19, ale dla LDAP. Endpoint test wykonuje bind + lookup.

Stworz drugi profile LDAP (re-uzywa default ldap secret ref):

```bash
LDAP_ID=$(curl -k -sS -X POST https://127.0.0.1:3000/identity-config/ldap-profiles \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"Lab secondary LDAP",
    "description":"Test profile",
    "isActive":true,
    "host":"192.168.20.40",
    "port":389,
    "tlsMode":"disabled",
    "bindDn":"cn=admin,dc=raptorgate,dc=local",
    "bindPasswordRef":"secret://identity/ldap/default",
    "userBaseDn":"ou=users,dc=raptorgate,dc=local",
    "userFilterAttribute":"uid",
    "groupBaseDn":"ou=groups,dc=raptorgate,dc=local",
    "groupMemberAttribute":"memberUid",
    "groupNameAttribute":"cn",
    "timeoutMs":3000,
    "cacheTtlSeconds":60
  }' | jq -r '.data.ldapServerProfiles[] | select(.name=="Lab secondary LDAP") | .id')
echo "$LDAP_ID"
```

Test endpoint:

```bash
curl -k -sS -X POST "https://127.0.0.1:3000/identity-config/ldap-profiles/$LDAP_ID/test" \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"username":"user"}' | jq
```

Oczekiwane: `data.outcome:"accept"`, lista grup zawiera `users`. Bez hasla — bind to LDAP search uzywa bind DN profilu, nie hasla uzytkownika.

## ID-21 - Auth profile provider=ldap (LDAP-only portal)

Cel: provider `ldap` autentykuje wylacznie przez LDAP simple bind, bez RADIUS-a.

Stworz auth profile `ldap`:

```bash
LDAP_AUTH_ID=$(curl -k -sS -X POST https://127.0.0.1:3000/identity-config/authentication-profiles \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d "{
    \"name\":\"Portal LDAP only\",
    \"description\":\"LDAP simple bind\",
    \"isActive\":true,
    \"provider\":\"ldap\",
    \"radiusProfileId\":null,
    \"ldapProfileId\":\"$LDAP_ID\",
    \"groupSource\":\"ldap\",
    \"sessionTtlSeconds\":1800
  }" | jq -r '.data.authenticationProfiles[] | select(.name=="Portal LDAP only") | .id')
echo "$LDAP_AUTH_ID"
```

Przepnij portal na nowy profile:

```bash
curl -k -sS -X PATCH https://127.0.0.1:3000/identity-config/settings \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"portalAuthenticationProfileId\":\"$LDAP_AUTH_ID\"}" | jq '.data.settings'
```

Oczekiwane: `portalAuthenticationProfileId` ma nowe ID.

Na `h1`:

```bash
curl -k -sS -X POST https://192.168.10.254/api/identity/logout
curl -k -sS -i -X POST https://192.168.10.254/api/identity/login \
  -H 'content-type: application/json' \
  -d '{"username":"user","password":"user123"}'
```

Oczekiwane: HTTP `201`, body envelope z `data.username:"user"`.

Na `r1`:

```bash
sudo grep -E 'auth.engine.result|auth.ldap.bind' /var/log/raptorgate/backend/$(date +%F).log | tail -5
```

Oczekiwane: log pokazuje `provider:"ldap"`, brak `auth.radius.access_accept` dla tego loginu.

Wroc portal do default-portal-radius:

```bash
curl -k -sS -X PATCH https://127.0.0.1:3000/identity-config/settings \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"portalAuthenticationProfileId":"default-portal-radius"}'
```

## ID-22 - Auth profile provider=local (lokalny user przez portal)

Cel: provider `local` autentykuje uzytkownikow z lokalnego user repo (panel admin), bez RADIUS-a/LDAP-a.

Stworz lokalnego usera w panelu admin (jezeli nie ma - mozesz uzyc istniejacego):

```bash
curl -k -sS -X POST https://127.0.0.1:3000/users \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"username":"portal-local","password":"local-pass","roles":["viewer"]}' | jq
```

Oczekiwane: `201` z `data.user.username:"portal-local"`.

Stworz auth profile `local`:

```bash
LOCAL_AUTH_ID=$(curl -k -sS -X POST https://127.0.0.1:3000/identity-config/authentication-profiles \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"Portal local users",
    "description":"Local users for portal",
    "isActive":true,
    "provider":"local",
    "radiusProfileId":null,
    "ldapProfileId":null,
    "groupSource":"none",
    "sessionTtlSeconds":1800
  }' | jq -r '.data.authenticationProfiles[] | select(.name=="Portal local users") | .id')
```

Przepnij portal:

```bash
curl -k -sS -X PATCH https://127.0.0.1:3000/identity-config/settings \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"portalAuthenticationProfileId\":\"$LOCAL_AUTH_ID\"}"
```

Na `h1`:

```bash
curl -k -sS -i -X POST https://192.168.10.254/api/identity/login \
  -H 'content-type: application/json' \
  -d '{"username":"portal-local","password":"local-pass"}'
```

Oczekiwane: HTTP `201`, sesja ma `username:"portal-local"`, `groups:[]`.

Sprawdz, ze RADIUS user `user/user123` nie przejdzie przez ten profile:

```bash
curl -k -sS -i -X POST https://192.168.10.254/api/identity/login \
  -H 'content-type: application/json' \
  -d '{"username":"user","password":"user123"}'
```

Oczekiwane: HTTP `401` — RADIUS-only userow nie ma w lokalnej bazie.

Wroc portal:

```bash
curl -k -sS -X PATCH https://127.0.0.1:3000/identity-config/settings \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"portalAuthenticationProfileId":"default-portal-radius"}'
```

## ID-23 - Inactive auth profile odrzuca login

Cel: `isActive:false` na profilu wskazywanym przez settings = `misconfigured`, nie `accept`.

Wylacz default-portal-radius:

```bash
curl -k -sS -X PUT https://127.0.0.1:3000/identity-config/authentication-profiles/default-portal-radius \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"Default portal RADIUS",
    "description":"Seeded from environment",
    "isActive":false,
    "provider":"radius",
    "radiusProfileId":"default-radius",
    "ldapProfileId":"default-ldap",
    "groupSource":"ldap",
    "sessionTtlSeconds":1800
  }'
```

Na `h1`:

```bash
curl -k -sS -i -X POST https://192.168.10.254/api/identity/login \
  -H 'content-type: application/json' \
  -d '{"username":"user","password":"user123"}'
```

Oczekiwane: HTTP `503` lub `500` z `message` zawierajacym `inactive`. Logi backendu maja `auth.engine.result` z `result:"misconfigured"`.

Przywroc:

```bash
curl -k -sS -X PUT https://127.0.0.1:3000/identity-config/authentication-profiles/default-portal-radius \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"Default portal RADIUS",
    "description":"Seeded from environment",
    "isActive":true,
    "provider":"radius",
    "radiusProfileId":"default-radius",
    "ldapProfileId":"default-ldap",
    "groupSource":"ldap",
    "sessionTtlSeconds":1800
  }'
```

## ID-24 - Delete profilu w uzyciu zwraca 409

Cel: nie da sie usunac auth profile, ktory wskazuje settings; nie da sie usunac RADIUS/LDAP profile, ktory wskazuje auth profile.

Usuniecie default-portal-radius (wskazywany przez settings):

```bash
curl -k -sS -i -X DELETE https://127.0.0.1:3000/identity-config/authentication-profiles/default-portal-radius \
  -H "authorization: Bearer $ACCESS_TOKEN"
```

Oczekiwane: HTTP `409`, message zawiera `in use` / `referenced`.

Usuniecie default-radius (wskazywany przez auth profile):

```bash
curl -k -sS -i -X DELETE https://127.0.0.1:3000/identity-config/radius-profiles/default-radius \
  -H "authorization: Bearer $ACCESS_TOKEN"
```

Oczekiwane: HTTP `409`.

Usuniecie nieuzywanego profilu z ID-19 dziala:

```bash
curl -k -sS -i -X DELETE "https://127.0.0.1:3000/identity-config/radius-profiles/$RADIUS_ID" \
  -H "authorization: Bearer $ACCESS_TOKEN"
```

Oczekiwane: HTTP `200`, profile znika z `getIdentityConfig`.

## ID-25 - Identity sessions admin API

Cel: admin widzi i revokuje sesje runtime z panelu.

Warunek: aktywna sesja `user` z ID-06.

List:

```bash
curl -k -sS https://127.0.0.1:3000/identity-sessions \
  -H "authorization: Bearer $ACCESS_TOKEN" | jq '.data.sessions[] | {sessionId, username, ipAddress, expiresAt}'
```

Oczekiwane: lista zawiera sesje dla `192.168.10.10`, `username:"user"`.

Revoke przez `sourceIp`:

```bash
curl -k -sS -X POST https://127.0.0.1:3000/identity-sessions/revoke \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"sourceIp":"192.168.10.10"}' | jq
```

Oczekiwane: `data.removed:true`.

Na `h1`:

```bash
curl -k -sS https://192.168.10.254/api/identity/session
curl --connect-timeout 3 -m 5 -i http://192.168.20.10:8080/api/ping
```

Oczekiwane: `data.authenticated:false`, ruch dropowany.

Revoke bez `sessionId` ani `sourceIp`:

```bash
curl -k -sS -i -X POST https://127.0.0.1:3000/identity-sessions/revoke \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{}'
```

Oczekiwane: HTTP `400`, message `sessionId or sourceIp is required`.

## ID-26 - Group source `radius_vsa`

Cel: gdy `groupSource:"radius_vsa"`, backend bierze grupy z atrybutow VSA RADIUS-a, nie z LDAP-a.

Warunek wstepny: serwer RADIUS musi zwracac `Filter-Id` albo `Class` z grupami (lab freeradius musi byc skonfigurowany — sprawdz `/etc/freeradius/3.0/users` na vm `radius`).

Stworz auth profile z `groupSource:"radius_vsa"`:

```bash
VSA_AUTH_ID=$(curl -k -sS -X POST https://127.0.0.1:3000/identity-config/authentication-profiles \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"Portal RADIUS VSA",
    "description":"Groups from RADIUS attributes",
    "isActive":true,
    "provider":"radius",
    "radiusProfileId":"default-radius",
    "ldapProfileId":null,
    "groupSource":"radius_vsa",
    "sessionTtlSeconds":1800
  }' | jq -r '.data.authenticationProfiles[] | select(.name=="Portal RADIUS VSA") | .id')

curl -k -sS -X PATCH https://127.0.0.1:3000/identity-config/settings \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"portalAuthenticationProfileId\":\"$VSA_AUTH_ID\"}"
```

Na `h1`:

```bash
curl -k -sS -X POST https://192.168.10.254/api/identity/logout
curl -k -sS -i -X POST https://192.168.10.254/api/identity/login \
  -H 'content-type: application/json' \
  -d '{"username":"user","password":"user123"}'
curl -k -sS https://192.168.10.254/api/identity/session
```

Oczekiwane: jezeli RADIUS nie zwraca grup, `data.groups:[]` i polityki na `identity_group=users` zablokuja ruch. Jezeli zwraca, `groups` zawiera wartosci z VSA. Logi backendu `identity.groups.resolved` ma `source:"radius_vsa"`.

Wroc portal do defaultu i posprzataj:

```bash
curl -k -sS -X PATCH https://127.0.0.1:3000/identity-config/settings \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"portalAuthenticationProfileId":"default-portal-radius"}'
curl -k -sS -X DELETE "https://127.0.0.1:3000/identity-config/authentication-profiles/$VSA_AUTH_ID" \
  -H "authorization: Bearer $ACCESS_TOKEN"
```

## ID-27 - Wiele profili admin login + adminRoleMappings

Cel: drugi profile dla `adminAuthenticationProfileId` z innym mappingiem; switch zmienia, kto dostaje admin role.

Profile A (ldap_group=admins → admin):

```bash
ADMIN_PROF_A=$(curl -k -sS -X POST https://127.0.0.1:3000/identity-config/authentication-profiles \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"Admin RADIUS A",
    "description":"admins -> admin",
    "isActive":true,
    "provider":"radius",
    "radiusProfileId":"default-radius",
    "ldapProfileId":"default-ldap",
    "groupSource":"ldap",
    "sessionTtlSeconds":1800,
    "adminRoleMappings":[{"matchType":"ldap_group","matchValue":"admins","role":"admin"}]
  }' | jq -r '.data.authenticationProfiles[] | select(.name=="Admin RADIUS A") | .id')
```

Profile B (ldap_group=admins → viewer):

```bash
ADMIN_PROF_B=$(curl -k -sS -X POST https://127.0.0.1:3000/identity-config/authentication-profiles \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"Admin RADIUS B",
    "description":"admins -> viewer",
    "isActive":true,
    "provider":"radius",
    "radiusProfileId":"default-radius",
    "ldapProfileId":"default-ldap",
    "groupSource":"ldap",
    "sessionTtlSeconds":1800,
    "adminRoleMappings":[{"matchType":"ldap_group","matchValue":"admins","role":"viewer"}]
  }' | jq -r '.data.authenticationProfiles[] | select(.name=="Admin RADIUS B") | .id')
```

Switch admin na A:

```bash
curl -k -sS -X PATCH https://127.0.0.1:3000/identity-config/settings \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"adminAuthenticationProfileId\":\"$ADMIN_PROF_A\"}"
curl -k -sS -X POST https://127.0.0.1:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"admin1234"}' | jq '.data | {roles, authProvider}'
```

Oczekiwane: `roles:["admin"]`, `authProvider:"radius"`.

Switch admin na B:

```bash
curl -k -sS -X PATCH https://127.0.0.1:3000/identity-config/settings \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"adminAuthenticationProfileId\":\"$ADMIN_PROF_B\"}"
curl -k -sS -X POST https://127.0.0.1:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"admin1234"}' | jq '.data | {roles, authProvider}'
```

Oczekiwane: `roles:["viewer"]`. Lokalny break-glass admina nadal jest dostepny przez `admin/<lokalne haslo>`.

Posprzataj:

```bash
curl -k -sS -X PATCH https://127.0.0.1:3000/identity-config/settings \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"adminAuthenticationProfileId":null}'
curl -k -sS -X DELETE "https://127.0.0.1:3000/identity-config/authentication-profiles/$ADMIN_PROF_A" -H "authorization: Bearer $ACCESS_TOKEN"
curl -k -sS -X DELETE "https://127.0.0.1:3000/identity-config/authentication-profiles/$ADMIN_PROF_B" -H "authorization: Bearer $ACCESS_TOKEN"
```

## ID-28 - Brak admin profile = blokada zewnetrznego admin loginu

Cel: gdy `adminAuthenticationProfileId:null`, login zewnetrznego admina jest niemozliwy, ale lokalny break-glass dziala.

Upewnij sie, ze admin pointer jest pusty:

```bash
curl -k -sS -X PATCH https://127.0.0.1:3000/identity-config/settings \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"adminAuthenticationProfileId":null}'
```

Login RADIUS-only admina (brak w lokalnej bazie):

```bash
curl -k -sS -i -X POST https://127.0.0.1:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"radius-only-admin","password":"x"}'
```

Oczekiwane: HTTP `401` z `Invalid credentials`.

Lokalny `admin` ze swoim haslem przechodzi:

```bash
curl -k -sS -i -X POST https://127.0.0.1:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"admin"}'
```

Oczekiwane: HTTP `201` z `roles` z lokalnej bazy.

## ID-29 - Sprzatanie po ID-19..ID-28

Po skonczonych testach skasuj sztuczne profile:

```bash
curl -k -sS -X DELETE "https://127.0.0.1:3000/identity-config/ldap-profiles/$LDAP_ID" -H "authorization: Bearer $ACCESS_TOKEN"
curl -k -sS -X DELETE "https://127.0.0.1:3000/identity-config/authentication-profiles/$LDAP_AUTH_ID" -H "authorization: Bearer $ACCESS_TOKEN"
curl -k -sS -X DELETE "https://127.0.0.1:3000/identity-config/authentication-profiles/$LOCAL_AUTH_ID" -H "authorization: Bearer $ACCESS_TOKEN"
```

Sprawdz koncowy stan:

```bash
curl -k -sS https://127.0.0.1:3000/identity-config -H "authorization: Bearer $ACCESS_TOKEN" | jq '.data | {radius:[.radiusServerProfiles[].id], ldap:[.ldapServerProfiles[].id], auth:[.authenticationProfiles[].id], settings:.settings}'
```

Oczekiwane: zostaja tylko `default-radius`, `default-ldap`, `default-portal-radius`. Settings: portal=`default-portal-radius`, admin=null.

## Kryterium koncowe flow demo

Minimalny zielony scenariusz Issue 1-7:

1. `ID-01` i `ID-02` przechodza.
2. `ID-03`: h1 -> h2 jest zablokowane bez sesji.
3. `ID-06`: login `user/user123` tworzy sesje, grupy `users`, firewall dostaje upsert, h1 -> h2 przechodzi.
4. `ID-08`: logout usuwa sesje, firewall dostaje revoke, h1 -> h2 znow jest blokowane.
5. `ID-09`: `guest/guest123` loguje sie poprawnie, ale grupa `guests` jest blokowana przez polityke.
6. `ID-10`: po `expiresAt` nowy ruch jest blokowany bez restartu firewalla.
7. `ID-13`: po restarcie backendu sesja zostaje aktywna, a po restarcie firewalla wraca po cyklu replay bez reloginu.
8. `ID-14`: login/logout nie dotyka config snapshotow.
9. `ID-15`: resolver stref nie zalezy od labowych subnetow.
10. `ID-16`: portal listener zapisuje sie w identity configu.
11. `ID-17`: admin login przez RADIUS dziala tylko z jawnie zmapowana rola.

Rozszerzony scenariusz pokrywajacy zarzadzanie profilami:

12. `ID-18`: lokalny admin dostaje access token i widzi caly identity config.
13. `ID-19` + `ID-19a`: RADIUS server profile CRUD i `/test` (Access-Accept i Access-Reject) bez tworzenia sesji.
14. `ID-20`: LDAP server profile CRUD i `/test` (bind + lookup z grupami).
15. `ID-21`: provider `ldap` autentykuje portalowo bez RADIUS-a, log pokazuje `provider:"ldap"`.
16. `ID-22`: provider `local` przepuszcza lokalnego usera w portalu i odrzuca RADIUS-only.
17. `ID-23`: `isActive:false` na aktywnym profilu = portal odrzuca login jako misconfigured.
18. `ID-24`: delete profilu wskazywanego przez settings/auth profile zwraca `409`, delete nieuzywanego `200`.
19. `ID-25`: `/identity-sessions` listuje sesje runtime, revoke po `sourceIp` blokuje ruch.
20. `ID-26`: `groupSource:"radius_vsa"` pomija LDAP, grupy lecą z atrybutow RADIUS.
21. `ID-27`: switch `adminAuthenticationProfileId` zmienia `adminRoleMappings` live.
22. `ID-28`: `adminAuthenticationProfileId:null` blokuje zewnetrzny admin login, lokalny break-glass dziala.
23. `ID-29`: po sprzataniu zostaja tylko domyslne profile.
