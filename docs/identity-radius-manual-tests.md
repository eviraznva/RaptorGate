# Manualne testy identity/RADIUS MVP

Zakres: weryfikacja implementacji identity/RADIUS bez uruchamiania skryptow testowych. Komendy sa celowo pojedynczymi krokami do wykonania recznie w VM-kach.

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
| `admin` | `admin123` | `admins` |
| `user` | `user123` | `users` |
| `guest` | `guest123` | `guests` |

Przy logowaniu przez portal backend musi widziec `sourceIp=192.168.10.10`. Nie wysylamy `sourceIp` w body.

Komendy `vagrant` wykonuj z katalogu `vagrant/`. Do maszyn wchodzisz recznie przez `vagrant ssh h1`, `vagrant ssh r1`, `vagrant ssh h2`, `vagrant ssh radius` albo `vagrant ssh ldap`.

## Przygotowanie

1. Sprawdz, ze VM-ki stoja:

```bash
vagrant status
```

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
radtest admin admin123 192.168.20.30 0 radiussecret
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

## ID-04 - Portal jest dostepny, a status sesji jest anonymous

Cel: portal ma byc dostepny z h1 mimo pre-auth gate.

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

## ID-05 - Zle haslo nie tworzy sesji

Cel: Access-Reject z RADIUS nie tworzy sesji backendu ani firewalla.

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

## ID-06 - Poprawny login tworzy sesje i pozwala na h1 -> h2

Cel: backend wykonuje RADIUS auth, pobiera grupy z LDAP, tworzy sesje i synchronizuje firewall.

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

## ID-09 - Guest ma sesje, ale polityka blokuje grupe guests

Cel: `identity_group` w RaptorLang blokuje `guests`, mimo poprawnego RADIUS loginu.

Najpierw wyloguj ewentualna sesje:

```bash
curl -k -sS -X POST https://192.168.10.254/api/identity/logout
```

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
curl -k -sS -i -X POST https://127.0.0.1:3000/auth/login -H 'content-type: application/json' -d '{"username":"admin","password":"admin123"}'
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
curl -k -sS -i -X POST https://127.0.0.1:3000/auth/login -H 'content-type: application/json' -d '{"username":"admin","password":"admin123"}'
```

Oczekiwane:

- login zewnetrzny jest odrzucony
- backend loguje `auth.admin.authorization_denied`
- lokalny break-glass admin nadal moze zalogowac sie lokalnym haslem, nawet gdy RADIUS jest niedostepny

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
