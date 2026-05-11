# ADR 0005: Zrodlo grup identity — LDAP jako source of truth, RADIUS VSA jako fallback

Status: zaakceptowane
Data: 2026-04-26
Kontekst: Issue 4 (LDAP group mapping and optional RADIUS VSA)

## Decyzja

Auth uzytkownika i model `user -> groups` to dwa rozne kontrakty po stronie
backendu. RADIUS odpowiada wylacznie za auth (Issue 3); LDAP jest docelowym
zrodlem grup do polityk identity. RADIUS VSA pozostaje opcjonalnym shortcutem,
zgodnie z planem Issue 4 (MVP / fallback).

Wprowadzamy `IdentityGroupResolverService` (warstwa aplikacji) z deterministyczna
priorytetyzacja:

1. `IDENTITY_LDAP_ENABLED=false` lub `IDENTITY_GROUP_SOURCE_PRIMARY=vsa` →
   uzywamy grup z RADIUS VSA (Filter-Id, Class, Cisco AVPair `shell:roles`,
   Issue 3). Brak VSA = `source=none`, polityki widza pusta liste grup.
2. LDAP enabled i primary=ldap (default) →
   - cache hit → grupy z `InMemoryLdapGroupCache` (TTL
     `IDENTITY_LDAP_GROUP_CACHE_TTL_SECONDS`, default 5 min).
   - cache miss → bind admin + dwa search-e (`uid=$user`, `memberUid=$user`)
     przez `TcpLdapDirectoryAdapter`. Wynik zapisywany w cache.
   - `not-found` lub blad LDAP (timeout, refused, bind reject) → fallback do VSA,
     ze sledzeniem `ldapDiagnostic` i `ldapError` w logach.

`identityUserId` przekazywany do firewalla pochodzi z resolvera: LDAP DN gdy
`source=ldap`, inaczej username. Issue 8 zwiaze go z trwalym `IdentityUser`
do audytu/UI.

## Konsekwencje

- Polityki (Issue 6) pytaja sesje firewalla o pole `groups`, ktore juz dawno
  jest zsynchronizowane z LDAP. Nie potrzebuja znac LDAP-a ani VSA.
- "Zmiana grup nie wymaga relogowania" realizuje
  `IdentityGroupRefresherService`: cyklicznie (`IDENTITY_GROUP_REFRESH_INTERVAL_MS`,
  default 60 s) iteruje aktywne sesje, woła resolver i — gdy grupy sie roznia —
  wysyla `UpsertIdentitySession` do firewalla z tym samym `session_id`. Lifecycle
  sesji nie jest naruszony (ADR 0003: renew = idempotentny upsert).
- Cache LDAP zyje w pamieci backendu i niczego nie persystuje (analogicznie do
  runtime sesji w ADR 0002). Restart backendu czysci cache; pierwsze zapytania
  po starcie pojda do LDAP.
- LDAP lookup nie jest na hot pathie pakietu — firewall nigdy nie pyta LDAP-a
  (ADR 0001). Backend ladowac sie szybciej, gdy refresher i auth path uzywaja
  cache.
- Bledy LDAP sa **diagnostyczne, nie krytyczne**: backend kontynuuje z VSA
  (jesli skonfigurowane) lub tworzy sesje bez grup. Loguje `event=identity.ldap.error`
  z `username` i bledem; admin UI (Issue 8) bedzie miec zrodlo do dashboardu
  identity. Login nie jest blokowany przez awarie LDAP — to swiadoma decyzja:
  raz uwierzytelniony uzytkownik dostaje sesje, polityka domyslnie defaultowa do
  zachowania post-auth dla unknown groups.
- Klient LDAPv3 zaimplementowany od zera w `infrastructure/adapters/ldap/`:
  `ldap-message.ts` (BER + TLV) i `tcp-ldap-client.ts` (transport TCP).
  Zakres ograniczony do `bind simple auth`, `search equalityMatch`, `unbind`.
  Spojne ze stylem `radius-packet.ts` (Issue 3, RFC 2865 od zera) — nie chcemy
  dodawac nowej zaleznosci bibliotecznej dla 3 typow operacji LDAP.

## Alternatywy odrzucone

- **VSA jako jedyne zrodlo grup**: RADIUS VSA wymaga konfiguracji po stronie
  RADIUS-a (Cisco AVPair, Filter-Id), co laczy "kto jest userem" z "jakie ma
  grupy" w jednym kanale. Nie pasuje do separacji control plane (ADR 0001) i
  utrudnia zmiane grup bez relogowania.
- **Group cache trzymany w sesji identity**: laczy lifecycle sesji z
  lifecyclem grup, czyli zmiana grup wymagalaby relogowania. Wprost wykluczone
  przez kryteria Issue 4.
- **LDAP search dla kazdego pakietu w firewallu**: lamie ADR 0001 (data plane
  ma byc agnostyczne wzgledem providerow identity), pakuje bind sekrety do
  data plane i wprowadza LDAP na hot path.
- **Biblioteka `ldapts`/`ldapjs`**: nowa zaleznosc i pelnowymiarowy klient,
  podczas gdy uzywamy 3 operacji. Pisanie minimum sami pasuje do stylu
  `radius-packet.ts` i daje peln a kontrole nad bledami.
- **LDAP jako tez auth (zamiast RADIUS)**: backend mialby dwa scieznicze do
  uwierzytelniania, a sesja identity nie wymaga logiki LDAP-bind. Zostawiamy
  RADIUS dla auth, LDAP dla grup, zgodnie z planem Issue 4.
