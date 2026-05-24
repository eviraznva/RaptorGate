# Identity enforcement: RADIUS + LDAP manual frontend tests

Zakres: reczne potwierdzenie, ze frontend potrafi skonfigurowac RADIUS, LDAP, profile logowania i portal tak, zeby firewall egzekwowal `auth_state` oraz `identity_group`.

## Dane labowe

- Dashboard: `https://192.168.56.254`
- Admin lokalny: `admin` / `Test1234` (jesli zmieniony, uzyj aktualnego hasla admina)
- Portal: `https://192.168.10.254/portal/login`
- Chroniony serwis h2: `http://192.168.20.10:8080/api/ping`
- RADIUS: `192.168.20.30:1812`, secret `radiussecret`
- LDAP: `192.168.20.40:389`, bind DN `cn=admin,dc=raptorgate,dc=local`, bind password `admin`

Konta:

| User | Password | LDAP group |
| --- | --- | --- |
| `user` | `user123` | `users` |
| `guest` | `guest123` | `guests` |

Do testow enforcementu portal musi widziec klienta jako `192.168.10.10`, czyli ruch portalu i h2 najlepiej puszczac z `h1` albo z przegladarki przez SOCKS/PAC przez `h1`.

## Przygotowanie

1. Upewnij sie, ze h2 HTTP dziala:

```bash
cd vagrant
vagrant ssh h2 -c "sudo systemctl restart h2-http && systemctl is-active h2-http"
```

2. Zaloguj sie do dashboardu jako admin i wejdz w `Identity`.

3. W `Policy Engine` przygotuj jedna aktywna regule enforcementu dla domyslnego zone-pair. Tymczasowo wylacz broad allow-all reguly, bo inaczej test blokowania nie ma sensu.

```text
match auth_state {
  = authenticated:
    match identity_group {
      = "users":
        match protocol {
          = tcp:
            match dst_port {
              = 8080: verdict allow
              _: verdict drop
            }
          _: verdict drop
        }
      _: verdict drop
    }
  _: verdict drop
}
```

4. Wejdz w `Config` -> `Apply`, zostaw `isActive=true`, ustaw `changeSummary`, kliknij `Apply Snapshot`.

## FE-ID-01: RADIUS profile i diagnostics

W `Identity` -> `RADIUS Profiles` utworz albo zaktualizuj profil:

- Name: `test-env-radius-enforcement`
- Active: enabled
- Host: `192.168.20.30`
- Port: `1812`
- Timeout ms: `1500`
- Retries: `1`
- Shared secret ref: `secret://identity/radius/test-radius-enforcement`
- Set shared secret: `radiussecret`
- NAS IP: `192.168.20.254`
- NAS identifier: `raptorgate-test-env`
- Called station ID: `test-env-portal`

Potem `Identity` -> `Diagnostics`:

- RADIUS profile: `test-env-radius-enforcement`
- Username: `user`
- Password: `user123`
- Calling station ID: `192.168.10.10`

Oczekiwane: test konczy sie sukcesem/accept. Dla hasla `wrong-password` wynik ma byc reject, bez tworzenia sesji.

## FE-ID-02: LDAP profile i diagnostics

W `Identity` -> `LDAP Profiles` utworz albo zaktualizuj profil:

- Name: `test-env-ldap-enforcement`
- Active: enabled
- Host: `192.168.20.40`
- Port: `389`
- TLS mode: `disabled`
- Bind DN: `cn=admin,dc=raptorgate,dc=local`
- Bind password ref: `secret://identity/ldap/test-ldap-enforcement`
- Set bind password: `admin`
- User base DN: `ou=users,dc=raptorgate,dc=local`
- User filter attribute: `uid`
- Group base DN: `ou=groups,dc=raptorgate,dc=local`
- Group member attribute: `memberUid`
- Group name attribute: `cn`
- Timeout ms: `1500`
- Cache TTL seconds: `60`

Potem `Identity` -> `Diagnostics`:

- LDAP profile: `test-env-ldap-enforcement`
- Username: `user`

Oczekiwane: test konczy sie sukcesem i pokazuje grupe `users`.

## FE-ID-03: RADIUS portal + LDAP groups, user allowed

1. W `Identity` -> `Authentication Profiles` utworz profil:

- Name: `test-env-radius-with-ldap-groups`
- Active: enabled
- Provider: `radius`
- RADIUS profile: `test-env-radius-enforcement`
- LDAP profile: `test-env-ldap-enforcement`
- Group source: `ldap`
- Session TTL seconds: `300`

2. W `Identity` -> `Portal Settings` wybierz `test-env-radius-with-ldap-groups` i zapisz listener:

- enabled: true
- interfaceName: `eth1`
- bindAddress: `192.168.10.254`
- bindPort: `443`

3. Z `h1` potwierdz blokade przed loginem:

```bash
cd vagrant
vagrant ssh h1 -c "curl -sS --connect-timeout 2 --max-time 4 http://192.168.20.10:8080/api/ping"
```

Oczekiwane: timeout albo blad polaczenia.

4. W portalu zaloguj `user` / `user123`.

5. W `Identity` -> `Active Sessions` oczekuj sesji:

- username: `user`
- source IP: `192.168.10.10`
- groups zawiera `users`

6. Z `h1` sprawdz ruch:

```bash
cd vagrant
vagrant ssh h1 -c "curl -sS --connect-timeout 2 --max-time 6 http://192.168.20.10:8080/api/ping"
```

Oczekiwane: `{"status":"ok"}`.

7. Wyloguj w portalu albo zrewokuj sesje w `Identity` -> `Active Sessions`.

8. Powtorz curl z `h1`.

Oczekiwane: timeout albo blad polaczenia.

## FE-ID-04: RADIUS portal + LDAP groups, guest blocked

1. Zaloguj w portalu `guest` / `guest123`.
2. W `Identity` -> `Active Sessions` oczekuj sesji z grupa `guests`.
3. Z `h1` sprawdz h2:

```bash
cd vagrant
vagrant ssh h1 -c "curl -sS --connect-timeout 2 --max-time 4 http://192.168.20.10:8080/api/ping"
```

Oczekiwane: login jest poprawny, ale ruch jest zablokowany przez `identity_group`.

## FE-ID-05: LDAP portal, user allowed

1. W `Identity` -> `Authentication Profiles` utworz profil:

- Name: `test-env-ldap-portal`
- Active: enabled
- Provider: `ldap`
- RADIUS profile: `None`
- LDAP profile: `test-env-ldap-enforcement`
- Group source: `ldap`
- Session TTL seconds: `300`

2. W `Identity` -> `Portal Settings` wybierz `test-env-ldap-portal` i zapisz.
3. Wyloguj/revokuj aktywna sesje.
4. Potwierdz blokade h1 -> h2 przed loginem.
5. W portalu zaloguj `user` / `user123`.
6. W `Active Sessions` oczekuj `user`, `192.168.10.10`, grupa `users`.
7. Curl z `h1` do `http://192.168.20.10:8080/api/ping` ma zwrocic `{"status":"ok"}`.
8. Wyloguj/revokuj sesje i potwierdz, ze ruch znow jest blokowany.

## FE-ID-06: LDAP portal, guest blocked

1. Zaloguj w portalu `guest` / `guest123`.
2. W `Active Sessions` oczekuj grupy `guests`.
3. Curl z `h1` do h2 ma byc zablokowany.

Oczekiwane: LDAP auth dziala, ale polityka przepuszcza tylko `identity_group="users"`.

## Sprzatanie

- W `Identity` -> `Active Sessions` zrewokuj sesje testowe.
- Przywroc poprzednia polityke albo ponownie wlacz reguly, ktore byly aktywne przed testem.
- W `Config` -> `Apply` opublikuj przywrocony snapshot.
