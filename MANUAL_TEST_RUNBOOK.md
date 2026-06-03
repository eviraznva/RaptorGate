# RaptorGate — ręczny runbook testowy (DNS, NAT + FTP ALG, Conntrack, IPS)

Krok‑po‑kroku: co kliknąć/wpisać w panelu (frontend) oraz jakie komendy odpalić na `h1`/`h2`,
żeby ręcznie zweryfikować moduły. Scenariusze odpowiadają testom e2e z `test-env/src/tests/`.

---

## Topologia i dostęp

```
 h1 (192.168.10.10)  ──intnet1──  r1 (NGFW)  ──intnet2──  h2 (192.168.20.10)
 strefa "clients"                 eth1 192.168.10.254                 strefa "servers"
                                  eth2 192.168.20.254
                                  eth3 192.168.56.254 (mgmt)
```

| Co | Adres |
|----|-------|
| Frontend (panel) | `https://192.168.56.254` |
| VictoriaLogs (logi NGFW) | `http://192.168.56.254:9428` |
| h1 (klient) | `192.168.10.10`, brama `192.168.10.254` |
| h2 (serwer: HTTP, vsftpd) | `192.168.20.10`, brama `192.168.20.254` |

Wejście na hosty (z katalogu `vagrant/`):

```bash
vagrant ssh h1
vagrant ssh h2
```

Strefy są już skonfigurowane: `clients` = `eth1` (h1), `servers` = `eth2` (h2).

> Po każdej zmianie konfiguracji w danej zakładce panelu kliknij **Apply / Zastosuj** —
> to wypycha snapshot do NGFW. Stan/diff snapshotów podejrzysz w **Config Control**.

---

## Krok 0 — polityka przepuszczająca ruch (wymagane!)

Bez reguły zezwalającej forward między strefami cały ruch h1↔h2 jest dropowany i żaden
poniższy test nie przejdzie.

**W panelu → Policy Engine:**
1. Dodaj/edytuj regułę dla pary stref `clients → servers`, priorytet `0`.
2. Treść (RaptorLang):
   ```
   match ip_ver {
       =v4: match protocol {
           |(=icmp =tcp =udp): verdict allow
       }
       = v6: verdict drop
   }
   ```
3. **Apply**.

**Weryfikacja (h1):**
```bash
ping -c2 192.168.20.10        # powinno odpowiadać
```

---

## 1. Conntrack (śledzenie połączeń)

**W panelu → Connection Tracking:** otwórz widok — będzie się odświeżać tabela sesji.

**Na h2 (serwer nasłuchujący):**
```bash
ncat -l -k 9999 -c 'echo HELLO'
```

**Na h1 (nawiąż sesję TCP):**
```bash
ncat --recv-only -w 3 192.168.20.10 9999
```

**Oczekiwany wynik:**
- h1 wypisuje `HELLO`.
- W **Connection Tracking** pojawia się przepływ
  `192.168.10.10 → 192.168.20.10:9999`, protokół TCP, ze stanem przechodzącym
  `SYN_SENT → ESTABLISHED`, a po zakończeniu `TIME_WAIT/CLOSE`.

ICMP też jest śledzony:
```bash
# h1
ping -c3 192.168.20.10
```
W tabeli pojawi się wpis ICMP z licznikami pakietów.

---

## 2. NAT (PAT, DNAT, SNAT, MASQUERADE)

Wszystkie reguły dodajesz w **panelu → NAT Rules → Add rule**. Wspólne pola: `isActive = on`,
`priority` (np. `10`), `protocol = TCP`. Po dodaniu/edycji — **Apply**.

> Usuwaj/wyłączaj poprzednią regułę NAT przed kolejnym scenariuszem (albo nadawaj różne
> priorytety), żeby reguły się nie nakładały.

### 2a. PAT — przekierowanie IP+port (VIP:8080 → h2:80)

**Panel → NAT Rules → akcja PAT:**
- `dstIp` = `192.168.20.200`
- `dstPort` = `8080`
- `translatedIp` = `192.168.20.10`
- `translatedPort` = `80`

**h2:**
```bash
python3 -m http.server 80 --bind 192.168.20.10
```
**h1:**
```bash
curl -s -o /dev/null -w '%{http_code}\n' --connect-timeout 5 192.168.20.200:8080
```
**Oczekiwane:** `200`.

### 2b. DNAT — przekierowanie po adresie docelowym (VIP:443 → h2:80)

**Panel → NAT Rules → akcja DNAT:**
- `dstCidr` = `192.168.20.200/32`
- `translatedIp` = `192.168.20.10`
- `translatedPort` = `80`

**h2:**
```bash
python3 -m http.server 80 --bind 192.168.20.10
```
**h1:**
```bash
curl -s -o /dev/null -w '%{http_code}\n' --connect-timeout 5 192.168.20.200:443
```
**Oczekiwane:** `200`. (Port 443 jest pod inspekcją TLS — NGFW automatycznie omija
przekierowanie TLS dla VIP‑a NAT, więc ruch trafia do h2.)

### 2c. SNAT — podmiana adresu źródłowego (h1 → 192.168.20.100)

**Panel → NAT Rules → akcja SNAT:**
- `srcCidr` = `192.168.10.0/24`
- `translatedIp` = `192.168.20.100`

**h2 (pokazuje widziane źródło):**
```bash
ncat -l 9999 -c 'echo PEER=$NCAT_REMOTE_ADDR'
```
**h1:**
```bash
ncat --recv-only -w 3 192.168.20.10 9999
```
**Oczekiwane:** `PEER=192.168.20.100` (h2 widzi przepisane źródło; NGFW samo nadaje
`192.168.20.100/32` na `eth2`, żeby odpowiadać na ARP).

### 2d. MASQUERADE — źródło = IP interfejsu wyjściowego (192.168.20.254)

**Panel → NAT Rules → akcja MASQUERADE:**
- `outInterface` = `eth2`
- `srcCidr` = `192.168.10.0/24`

**h2:**
```bash
ncat -l 9999 -c 'echo PEER=$NCAT_REMOTE_ADDR'
```
**h1:**
```bash
ncat --recv-only -w 3 192.168.20.10 9999
```
**Oczekiwane:** `PEER=192.168.20.254`.

> Po testach NAT wyłącz reguły (lub wyczyść w **Config Control**), żeby nie zaburzały
> kolejnych modułów.

---

## 3. FTP ALG (śledzenie kanału danych)

vsftpd działa na h2 (`192.168.20.10`), katalog anonimowy zawiera `raptorgate-ftp-test.txt`.
Wymagana tylko polityka z Kroku 0 (ALG działa na śledzonym ruchu FTP/21 i otwiera
oczekiwanie na kanał danych w trybie aktywnym).

**h1 — listing w trybie aktywnym (PORT):**
```bash
lftp -e 'set ftp:passive-mode off; set net:timeout 8; ls; bye' ftp://192.168.20.10
```
**Oczekiwane:** lista zawiera `raptorgate-ftp-test.txt`.

**h1 — pobranie pliku przez kanał danych ALG:**
```bash
lftp -e 'set ftp:passive-mode off; set net:timeout 8; cat /raptorgate-ftp-test.txt; bye' ftp://192.168.20.10
```
**Oczekiwane:** `RaptorGate FTP ALG test payload`.

**Weryfikacja w panelu → Connection Tracking:** obok sesji sterującej `:21` pojawia się
drugi przepływ kanału danych (port 20 / negocjowany port PORT) powiązany przez ALG
(stan/etykieta „related/expected"). Bez ALG aktywny tryb FTP byłby zablokowany.

---

## 4. DNS inspection (blocklist + tunneling)

DNS inspection analizuje zapytania DNS przechodzące przez NGFW (UDP/53, h1→h2).
Potrzebny prosty serwer DNS na h2.

**Na h2 — uruchom resolver odpowiadający na wszystko (jednorazowo):**
```bash
sudo apt-get install -y dnsmasq
sudo systemctl stop systemd-resolved 2>/dev/null || true
sudo dnsmasq -d -p 53 -A '/#/1.2.3.4'
```
(odpowiada `1.2.3.4` na dowolną domenę; zostaw w pierwszym terminalu)

**W panelu → DNS:**
1. **General**: `enabled = on`.
2. **Blocklist**: `enabled = on`, `domains = ["example.com", "*.tracking.local"]`.
3. **Apply**.

**h1 — domena spoza listy (przechodzi):**
```bash
dig +short +tries=1 +time=3 @192.168.20.10 google.com
```
**Oczekiwane:** `1.2.3.4`.

**h1 — domena z blocklisty (dropowana):**
```bash
dig +tries=1 +time=3 @192.168.20.10 example.com
```
**Oczekiwane:** brak odpowiedzi / timeout (zapytanie odrzucone przez NGFW).

**h1 — wildcard (`*.tracking.local`):**
```bash
dig +tries=1 +time=3 @192.168.20.10 foo.tracking.local   # blokada
dig +short +tries=1 +time=3 @192.168.20.10 tracking.local # apex — przechodzi (1.2.3.4)
```

**Tunneling detector** — w panelu DNS włącz zakładkę tunelowania (np. próg
`maxUniqueSubdomains`), **Apply**, potem na h1 zasymuluj flood losowych subdomen:
```bash
for i in $(seq 1 60); do
  dig +tries=1 +time=1 @192.168.20.10 "$(head -c 12 /dev/urandom | base64 | tr -dc 'a-z0-9').example.org" >/dev/null
done
```
**Oczekiwane:** po przekroczeniu progu zapytania zaczynają być blokowane (widoczne w logach).

**Wyłączenie master switcha** (General → `enabled = off`, Apply): `example.com` znów się
rozwiązuje (`1.2.3.4`) — potwierdza, że blokada to zasługa inspekcji.

---

## 5. IPS (sygnatury na ruchu przekazywanym)

**Na h2 — serwer HTTP do ataków (w `/tmp`):**
```bash
cd /tmp && python3 -u -m http.server 18080 --bind 0.0.0.0
```

**W panelu → IPS:**
1. **General**: `enabled = on`. **Detection**: `enabled = on`.
2. **Signatures → Add**:
   - `name` = `SQLi Union Select`
   - `matchType` = `regex`
   - `pattern` = `(?i)union\s+select`
   - `severity` = `high`
   - akcja = **drop/block**
   - `dstPorts` = `18080` (lub puste = wszystkie porty)
   - `enabled = on`
3. **Apply**.

**h1 — ruch nieszkodliwy (przechodzi):**
```bash
curl -s -o /dev/null -w 'STATUS=%{http_code}\n' --max-time 4 'http://192.168.20.10:18080/?q=hello'
```
**Oczekiwane:** `STATUS=200`.

**h1 — ładunek SQLi (blokowany):**
```bash
curl -s -o /dev/null -w 'STATUS=%{http_code}\n' --max-time 4 'http://192.168.20.10:18080/?q=UNION%20SELECT%201'
```
**Oczekiwane:** timeout / brak odpowiedzi (pakiet z dopasowaniem sygnatury dropowany).

**Wariant alert (zamiast drop):** ustaw akcję sygnatury na **alert**, Apply — ruch SQLi
przechodzi (`STATUS=200`), ale powstaje zdarzenie IPS (patrz logi/Dashboard).

**Wyłączenie:** Detection `enabled = off` (lub sygnatura `enabled = off`), Apply — ładunek
SQLi znów przechodzi, co potwierdza, że to IPS go blokował.

---

## Gdzie patrzeć na wyniki

- **Panel → Connection Tracking** — żywa tabela sesji (NAT, conntrack, kanały FTP ALG).
- **Panel → Dashboard** — alerty/zdarzenia (IPS, DNS, ML).
- **Panel → Config Control** — aktywny snapshot i diff konfiguracji.
- **VictoriaLogs** `http://192.168.56.254:9428` — logi NGFW. Przykładowe zapytania LogsQL:
  ```
  event:nat.kernel_coexist.applied
  event:conntrack.flow.new
  ips OR dns.blocklist.blocked
  ```

## Sprzątanie między testami

```bash
# h1/h2: ubij nasłuchy
sudo pkill -f 'http.server' ; sudo pkill -f ncat ; sudo pkill -f dnsmasq
```
W panelu wyłącz reguły NAT/IPS/DNS lub przywróć czysty snapshot w **Config Control**.
