# ADR 0004: Captive portal MVP — manualny URL i osobny vhost na interfejsie h1

Status: zaakceptowane
Data: 2026-04-26
Kontekst: Issue 7 (Captive portal MVP)

## Decyzja

Captive portal MVP nie przechwytuje dowolnego HTTPS i nie udaje detekcji NCSI.
Uzytkownik wchodzi recznie pod znany URL portalu, zaloguje sie haslem RADIUS,
a backend tworzy sesje identity i syncuje ja do firewalla (ADR 0001/0003).

Topologia:

- Portal jest hostowany jako **drugi nginx vhost** na r1, sluchajacy na
  `192.168.10.254:443` (interfejs h1 — eth1). Admin SPA pozostaje na vhoscie
  mgmt `192.168.56.254:443`, niedostepnym z h1.
- Vhost portalu ma swiadomie maly powierzchniowy zakres: `/portal/*` serwuje
  SPA, `/api/identity/*` proxuje do backendu na `127.0.0.1:3000/identity/*`,
  `/assets/*` pliki statyczne SPA, `/` -> 302 `/portal/login`. Wszystko inne
  (`/auth`, `/config`, `/dashboard`, ...) zwraca 404, zeby h1 nie widzialo
  reszty admin API ani admin SPA.
- Frontend i backend lezą za **tym samym** procesem nginx, dzieki czemu obie
  domeny (admin + portal) deploya ten sam dist SPA bez osobnego buildu.
- Backend dostaje source IP z `req.socket.remoteAddress`, a kiedy peer to
  127.0.0.1/::1 (nginx) — z ostatniego `X-Forwarded-For`. Klient nie podaje IP
  w body (Issue 3 wymaganie nadal obowiazuje).

Stan portalu jest **bezstanowy po stronie SPA** poza sesja w backendzie:
SPA pyta `GET /identity/session`, dostaje `authenticated: true|false` z
ewentualnymi `username`, `expiresAt`, `groups`. Stan UI pochodzi z odpowiedzi:

- `loading` — pierwszy fetch sesji
- `anonymous` z opcjonalnym `reason`: `expired`, `logged-out`, `rejected`,
  `unavailable` — formularz login + banner kontekstu
- `submitting` (login lub logout)
- `authenticated` z flaga `justLoggedIn` — panel z metadanymi sesji i
  przyciskiem Log out

Endpoint `GET /identity/session` traktuje wygasla sesje jako `authenticated:
false`, niezaleznie od tego czy backendowy sweeper juz ja sprzatnal — chroni
przed wyscigiem expiry/visit.

Pre-auth gate (Issue 5) nie blokuje portalu, bo ruch h1 -> 192.168.10.254:443
trafia w INPUT chain r1, a nie w FORWARD egzekwowany przez firewall. Polityka
identity dotyka tylko ruchu zone-pair (h1 -> h2) i tam wlasnie pojawia sie
"blocked -> login -> allowed -> logout/expire -> blocked".

## Konsekwencje

- Brak transparentnego przechwytywania HTTPS oznacza, ze MVP nie pokaze
  `you must log in` w przegladarce uzytkownika probujacego otworzyc h2.
  Zamiast tego polegamy na tym, ze admin/UX pokaze URL portalu (np. w
  szkoleniu / dashboardzie). Dla MVP wystarczy.
- Vhost portalu serwuje ten sam bundle SPA, co admin. Nie eksponujemy admin
  routes po sieciowemu, ale fizycznie pliki .js sa identyczne — bezpieczenstwo
  opiera sie na nginx location-based rejecting i na fakcie, ze admin endpoints
  (`/api/auth/*`, `/api/users/*`) nie sa proxowane na vhoscie portalu.
- Backend musi tolerowac, ze `req.ip` przyjdzie z proxy nginx — jest to juz
  obsluzone w `IdentityController.resolveSourceIp` (Issue 3).
- Nginx dziala jako jeden proces z dwoma vhostami; logi wspoldzielone w
  `/var/log/raptorgate/frontend/`. Tak jest dobrze dla labu, ale produkcja
  moglaby chciec rozdzielic loga portalu od loga admina.

## Alternatywy odrzucone

- **Drugi proces nginx tylko dla portalu**: prostsza separacja, ale zduplikowana
  konfiguracja TLS/cert i podwojny nadzor systemd. Wystarczy jeden nginx
  z dwoma server blockami.
- **Osobny build SPA tylko z portalem**: czystsza powierzchnia, ale wymaga
  osobnego entrypoint, osobnego pipelinea i bumpu w `vagrantfile`. Dla MVP
  szkoda zachodu.
- **Transparent HTTPS portal (intercept TLS)**: poza zakresem Issue 7
  (jawnie); wymagaloby wstrzykniecia w SSL inspection chain i splata sie z
  pinningiem.
- **Captive detection (Apple NCSI / Google `connectivitycheck`)**: poza
  zakresem MVP. Mozliwe w Issue 8 lub osobnym ticket'ie.
