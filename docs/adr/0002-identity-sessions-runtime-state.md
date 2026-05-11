# ADR 0002: Aktywne sesje identity to runtime state, nie config snapshot

Status: zaakceptowane
Data: 2026-04-24
Kontekst: Issue 1 (Lab and identity architecture)

## Decyzja

Aktywne sesje identity (mapowanie `client_ip -> user/groups/expires_at`) sa
**runtime state**, a nie czescia config snapshotu dystrybuowanego z backendu
do firewalla.

- Sesje powstaja z akcji uzytkownika (login przez portal) i znikaja z akcji
  uzytkownika lub uplywu czasu (logout, expire, revoke).
- Snapshot konfiguracji opisuje intencje administratora (polityki, zones,
  providery RADIUS/LDAP). Jest wersjonowany, wdrazany atomowo, rollbackowalny.
- Sesja uzytkownika nie jest intencja administratora i nie podlega temu samemu
  cyklowi dystrybucji.

## Konsekwencje

- `UpsertIdentitySession` / `RevokeIdentitySession` ida osobnym kanalem gRPC,
  niezaleznie od `PushConfigSnapshot` (Issue 2).
- Firewall trzyma aktywne sesje wylacznie w pamieci (keyed by client IP),
  bez zapisu do config store (Issue 2).
- Login/logout uzytkownika nie powoduje nowej wersji configu, nie triggeruje
  audytu config changes, nie pojawia sie w diffie snapshota.
- Po restarcie firewalla sesje sa odtwarzane przez replay z backendu (szczegoly
  lifecycle: Issue 2), nie przez zaladowanie snapshota.
- Panel admina pokazuje aktywne sesje z zapytan runtime, nie z config state
  (Issue 8).

## Alternatywy odrzucone

- Sesje w config snapshotcie: kazdy login robi nowa wersje config, audit log
  tonie w szumie, rollback configu przypadkiem wylogowuje uzytkownikow.
- Sesje trzymane tylko w backendzie, firewall pyta on-demand per pakiet:
  dodaje RTT do hot path, tworzy zaleznosc dostepnosci data plane od backendu.
