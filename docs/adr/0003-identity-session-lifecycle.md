# ADR 0003: Lifecycle aktywnej sesji identity

Status: zaakceptowane
Data: 2026-04-25
Kontekst: Issue 2 (Identity contracts and runtime sync)

## Decyzja

Sesja identity ma jeden wlasciciel stanu (backend jako control plane, ADR 0001)
i jeden runtime cache (firewall, ADR 0002). Kanalem sync jest gRPC
`IdentitySessionService` hostowany przez firewall na
`FIREWALL_QUERY_GRPC_SOCKET_PATH` (ten sam UDS co `FirewallQueryService`,
aby nie mnozyc kanalow).

Lifecycle sesji jest nastepujacy:

- **create**: po poprawnym loginie (portal -> backend -> RADIUS, Issue 3/7)
  backend tworzy sesje w swoim store i wola
  `UpsertIdentitySession(session)`. Firewall wpisuje rekord do in-memory
  store z kluczem `client_ip`. Jesli pod tym IP byla juz sesja, zostaje
  nadpisana (jedna sesja per IP, Issue 2).
- **renew**: backend decyduje o przedluzeniu (np. re-auth, keepalive).
  Renew to kolejny `UpsertIdentitySession` z tym samym `id` i nowym
  `expires_at`. RPC jest idempotentny dla tego samego `client_ip`.
- **expire**: firewall i backend egzekwuja `expires_at` niezaleznie.
  Backend w swoim sweeperze (Issue 3) wysyla `RevokeIdentitySession`
  po wygasnieciu. Firewall dodatkowo ignoruje pakiety ktorych sesja
  ma `expires_at <= now` na poziomie enforcementu (Issue 5), nawet jesli
  revoke jeszcze nie dotarl — nie polegamy na RTT do backendu.
- **revoke**: admin lub logout z portalu. Backend usuwa sesje ze swojego
  store i wola `RevokeIdentitySession(ip_address)`. Odpowiedz niesie
  `removed` — `true` gdy firewall faktycznie mial te sesje, `false` gdy
  nie bylo czego usuwac (brak sesji nie jest bledem, RPC jest tolerancyjne).
- **replay po restarcie firewalla**: firewall startuje z pustym runtime
  store. Backend, jako source of truth, wysyla `UpsertIdentitySession` dla
  kazdej wciaz waznej sesji (implementacja mechanizmu reconcile: Issue 3).
  ADR 0002 wyklucza zaladowanie tych sesji ze snapshota configu.

## Konsekwencje

- `ip_address` w `RevokeIdentitySession` to klucz store, a nie identyfikator
  sesji — trywializuje to wywolanie z backendu i chroni przed desyncem
  gdy backend stracil znajomosc `session_id` (np. crash po create).
- Brak TTL w firewallu: firewall honoruje `expires_at` pakietowo, ale nie
  uruchamia wlasnego sweepera. Sweeper zyje po stronie backendu (Issue 3),
  firewall tylko reaguje na przychodzace `Revoke` i ignoruje pakiety z
  wygasla sesja.
- Jeden kanal UDS dla `FirewallQueryService` i `IdentitySessionService`
  oznacza, ze tylko backend ma dostep — nie eksponujemy identity po TCP.
- Zadnych pisemnych trwalych struktur w firewallu: sesje gina przy restarcie
  i wracaja przez replay. Upraszcza to dyskowe disk store i audyt —
  snapshot configu nie zawiera sesji.

## Alternatywy odrzucone

- `Revoke` po `session_id` zamiast `ip_address`: backend musialby trzymac
  mapowanie `id -> ip` wylacznie dla tego RPC, a firewall i tak kluczuje
  po IP. Dodatkowy krok bez zysku.
- Sweeper w firewallu, ktory sam usuwa wygasle sesje: dublowalby
  odpowiedzialnosc backendu i utrudnial debug ("kto usunal sesje?").
  Enforcement per-pakiet po `expires_at` jest tansze i deterministyczne.
- Trwaly store sesji w firewallu (np. sqlite): wymusza atomowosc miedzy
  warstwami i psuje prostote "control plane = truth". Replay z backendu
  zalatwia uptime bez tego kosztu.
