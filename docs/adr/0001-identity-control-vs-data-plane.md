# ADR 0001: Backend to control plane identity, firewall to data plane enforcement

Status: zaakceptowane
Data: 2026-04-24
Kontekst: Issue 1 (Lab and identity architecture)

## Decyzja

Identity dzieli sie na dwie warstwy z wyraznym podzialem odpowiedzialnosci:

- **Backend (control plane)** jest jedynym zrodlem prawdy dla decyzji identity.
  Trzyma konfiguracje providerow (RADIUS, LDAP), wykonuje auth, zarzadza
  lifecycle sesji (create/renew/expire/revoke), rozwiazuje grupy uzytkownika.
  To tu dziala portal, polityka kto moze sie zalogowac, audit logi zdarzen
  identity.
- **Firewall (data plane enforcement)** konsumuje wynik decyzji backendu i
  egzekwuje go na pakietach. Trzyma lokalny lookup `client_ip -> (user, groups,
  auth_state, expires_at)` zasilany z backendu przez gRPC
  `IdentitySessionService` (Issue 2). Nie rozmawia bezposrednio z RADIUS/LDAP
  i nie robi auth sam.

## Konsekwencje

- Backend i firewall komunikuja sie wylacznie przez kontrakt gRPC
  `UpsertIdentitySession` / `RevokeIdentitySession`. Kazda inna droga
  (np. firewall pytajacy LDAP) jest anty-wzorcem.
- Firewall nie zna hasel, secretow RADIUS ani bindow LDAP.
- Wymiana providera identity (RADIUS -> OIDC itp.) dotyka tylko backendu, pod
  warunkiem ze kontrakt sesji do firewalla sie nie zmienia.
- Firewall pozostaje niezaleznie restartowalny; po restarcie backend replayuje
  aktywne sesje do firewalla (szczegoly lifecycle: Issue 2).

## Alternatywy odrzucone

- Firewall pytajacy LDAP/RADIUS bezposrednio: rozjezdza sciezki hot path,
  dubluje cache, wymusza konfig sekretow w data plane.
- Wspoldzielona baza sesji po stronie firewalla i backendu: miesza granice
  odpowiedzialnosci i wymusza spojnosc transakcyjna miedzy warstwami.
