# Manualne testy SSL inspection w środowisku Vagrant

Poniższe testy są przygotowane pod lab:

- `h1` = host zewnętrzny, `192.168.10.10`
- `r1` = firewall/router, `192.168.10.254` i `192.168.20.254`
- `h2` = host wewnętrzny, `192.168.20.10`

Testy są rozbite na trzy bloki:

1. ruch wychodzący lokalny: `h2 -> h1`
2. ruch wychodzący do Internetu bez `h1`: `h2 -> r1 -> Internet`
3. ruch przychodzący: `h1 -> h2`

Założenie: SSL inspection jest włączone na `r1`, a ruch TLS na porcie `443`
jest przekierowywany do lokalnego proxy MITM na `8443`.

## Szybki preflight

Na `r1` sprawdź, czy runtime SSL inspection jest podniesiony:

```bash
sudo systemctl status ngfw --no-pager
sudo systemctl status backend --no-pager
sudo nft list table inet raptorgate_tls
sudo ss -ltnp | grep -E ':(3000|8443)\b'
sudo ls -l /var/lib/raptorgate/pki/ca.crt /var/lib/raptorgate/pki/untrust_ca.crt
```

W osobnej konsoli na `r1` zostaw podgląd logów:

```bash
sudo journalctl -u ngfw -f -o cat | grep --line-buffered -E 'TlsInterceptStarted|InboundTlsInterceptStarted|TlsHandshakeComplete|InboundTlsHandshakeComplete|Decrypted traffic classified|HandshakeFailed|MITM TLS sessions established|Inbound TLS inspection|Outbound MITM intercepted'
```

Sukces preflightu:

- tabela `inet raptorgate_tls` istnieje
- `ngfw` nasłuchuje na `8443`
- w `/var/lib/raptorgate/pki/` istnieją `ca.crt` i `untrust_ca.crt`

## Ruch wychodzący

Cel: potwierdzić, że połączenie `h2 -> h1:443` jest terminowane na firewallu,
a klient po stronie `h2` widzi certyfikat wystawiony przez firewall, nie przez
oryginalny serwer na `h1`.

### 1. Uruchom serwer TLS na `h1`

Na `h1`:

```bash
mkdir -p /tmp/ssl-out
cd /tmp/ssl-out

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout h1-origin.key \
  -out h1-origin.crt \
  -days 7 \
  -subj '/CN=h1-origin.lab'

openssl x509 -in h1-origin.crt -noout -subject -issuer -fingerprint -sha256

sudo openssl s_server -accept 443 -cert h1-origin.crt -key h1-origin.key -www
```

Ten serwer zostaw uruchomiony.

### 2. Sprawdź certyfikat widziany przez klienta na `h2`

Na `h2`:

```bash
echo | openssl s_client \
  -connect 192.168.10.10:443 \
  -servername h1-origin.lab \
  -showcerts 2>/dev/null | \
openssl x509 -noout -subject -issuer -fingerprint -sha256
```

Oczekiwany wynik:

- `subject` nadal będzie wskazywał na `h1-origin.lab`
- `issuer` nie powinien być certyfikatem z `h1`
- dla self-signed upstream z tego testu powinieneś zobaczyć issuer
  `RaptorGate Untrust CA`

To oznacza, że klient na `h2` nie dostał oryginalnego certyfikatu z `h1`,
tylko certyfikat wygenerowany przez firewall.

### 3. Wymuś ruch HTTP wewnątrz TLS i sprawdź odpowiedź

Na `h2`:

```bash
printf 'GET / HTTP/1.1\r\nHost: h1-origin.lab\r\nConnection: close\r\n\r\n' | \
openssl s_client \
  -connect 192.168.10.10:443 \
  -servername h1-origin.lab \
  -quiet
```

Oczekiwany wynik:

- pojawi się odpowiedź z `openssl s_server -www`
- handshake może wypisać ostrzeżenie o niezaufanym issuerze
- samo połączenie i odpowiedź HTTP powinny przejść

### 4. Potwierdź inspekcję w logach `r1`

W logach `ngfw` na `r1` powinny pojawić się wpisy podobne do:

- `TlsInterceptStarted`
- `TlsHandshakeComplete`
- `MITM TLS sessions established`
- `Decrypted traffic classified`

Najlepszy sygnał, że DPI działa na odszyfrowanym ruchu:

- `Decrypted traffic classified`
- klasyfikacja `proto=http`

### Kryterium zaliczenia dla ruchu wychodzącego

Test uznaj za zaliczony, jeśli:

- klient na `h2` nie widzi oryginalnego issuera z `h1`
- połączenie `h2 -> h1` nadal zwraca odpowiedź HTTP
- `r1` loguje start handshake MITM i klasyfikację odszyfrowanego HTTP

## Ruch wychodzący do Internetu bez `h1`

Ten wariant zakłada, że:

- `h1` jest wyłączony albo po prostu nie bierze udziału w teście
- `r1` ma uplink do Internetu i NAT dla `192.168.20.0/24`
- `h2` nadal ma default route do `192.168.20.254`

Najwygodniejsze serwisy do takich testów:

- `sha256.badssl.com` do prostego testu certyfikatu TLS
- `www.howsmyssl.com` do odpowiedzi JSON po HTTPS
- `tls.peet.ws` do podglądu szczegółów klienta TLS i HTTP
- `www.wikipedia.org` jako znana publiczna strona z prostym testem HTTPS
- `www.google.com` jako popularny wariant opcjonalny

### 1. Szybki preflight łączności Internetowej

Na `r1`:

```bash
ip route show default
sudo nft list ruleset | grep -E 'masquerade|eth2'
```

Na `h2`:

```bash
ip route
ping -c 2 192.168.20.254
getent hosts sha256.badssl.com
```

Oczekiwany wynik:

- `r1` ma default route przez uplink Vagranta
- w rulesecie `nftables` na `r1` widać `masquerade` dla `192.168.20.0/24`
- `h2` ma default route przez `192.168.20.254`
- `sha256.badssl.com` rozwiązuje się na adres IP

### 2. Sprawdź certyfikat widziany przez `h2` dla publicznego serwera

Na `h2`:

```bash
echo | openssl s_client \
  -connect sha256.badssl.com:443 \
  -servername sha256.badssl.com \
  -showcerts 2>/dev/null | \
openssl x509 -noout -subject -issuer -fingerprint -sha256
```

Oczekiwany wynik:

- `subject` powinien wskazywać na `sha256.badssl.com`
- `issuer` po stronie klienta powinien być z firewalla, typowo `RaptorGate CA`
- `issuer` nie powinien być publicznym CA oryginalnego serwera

To oznacza, że `r1` przechwycił handshake i wystawił własny certyfikat MITM
dla publicznego upstreamu z zaufanym certyfikatem.

### 3. Wymuś HTTP wewnątrz TLS do `sha256.badssl.com`

Na `h2`:

```bash
printf 'GET / HTTP/1.1\r\nHost: sha256.badssl.com\r\nConnection: close\r\n\r\n' | \
openssl s_client \
  -connect sha256.badssl.com:443 \
  -servername sha256.badssl.com \
  -quiet
```

Oczekiwany wynik:

- pojawi się odpowiedź HTTP z publicznego serwisu
- klient może wypisać ostrzeżenie o lokalnie niezaufanym issuerze firewalla
- samo połączenie powinno przejść i zwrócić treść strony

### 4. Opcjonalnie sprawdź odpowiedź JSON z `How's My SSL?`

Na `h2`:

```bash
printf 'GET /a/check HTTP/1.1\r\nHost: www.howsmyssl.com\r\nConnection: close\r\n\r\n' | \
openssl s_client \
  -connect www.howsmyssl.com:443 \
  -servername www.howsmyssl.com \
  -quiet
```

Oczekiwany wynik:

- zwrócony payload będzie JSON-em
- w odpowiedzi powinny pojawić się pola podobne do `tls_version` i `rating`
- ruch nadal powinien być widoczny na `r1` jako odszyfrowany HTTP

### 5. Opcjonalnie sprawdź `tls.peet.ws`

Na `h2`:

```bash
printf 'GET /api/all HTTP/1.1\r\nHost: tls.peet.ws\r\nConnection: close\r\n\r\n' | \
openssl s_client \
  -connect tls.peet.ws:443 \
  -servername tls.peet.ws \
  -quiet
```

Oczekiwany wynik:

- zwrócony payload będzie JSON-em
- odpowiedź zwykle zawiera szczegóły TLS i HTTP widziane przez zewnętrzny serwer

### 6. Potwierdź inspekcję w logach `r1`

W logach `ngfw` na `r1` powinny pojawić się wpisy podobne do:

- `Outbound MITM intercepted`
- `TlsInterceptStarted`
- `MITM TLS sessions established`
- `TlsHandshakeComplete`
- `Decrypted traffic classified`

Najmocniejszy sygnał, że DPI działa na odszyfrowanym payloadzie:

- `Decrypted traffic classified`
- klasyfikacja `proto=Http`

### 7. Dodatkowy test na znanej publicznej stronie

Wariant rekomendowany: `www.wikipedia.org`

Na `h2`:

```bash
echo | openssl s_client \
  -connect www.wikipedia.org:443 \
  -servername www.wikipedia.org \
  -showcerts 2>/dev/null | \
openssl x509 -noout -subject -issuer -fingerprint -sha256
```

```bash
printf 'GET / HTTP/1.1\r\nHost: www.wikipedia.org\r\nConnection: close\r\n\r\n' | \
openssl s_client \
  -connect www.wikipedia.org:443 \
  -servername www.wikipedia.org \
  -quiet
```

Oczekiwany wynik:

- `subject` powinien wskazywać na `www.wikipedia.org`
- `issuer` po stronie klienta powinien być z firewalla
- odpowiedź HTTP powinna wrócić poprawnie
- na `r1` powinieneś zobaczyć `TlsHandshakeComplete` i `proto=Http`

### 8. Opcjonalny test na `www.google.com`

Na `h2`:

```bash
echo | openssl s_client \
  -connect www.google.com:443 \
  -servername www.google.com \
  -showcerts 2>/dev/null | \
openssl x509 -noout -subject -issuer -fingerprint -sha256
```

```bash
printf 'GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n' | \
openssl s_client \
  -connect www.google.com:443 \
  -servername www.google.com \
  -quiet
```

Oczekiwany wynik:

- `subject` powinien wskazywać na `www.google.com`
- `issuer` po stronie klienta powinien być z firewalla
- odpowiedź może być `200`, `301` albo `302`
- odpowiedź może zawierać dodatkowe nagłówki albo redirect, ale nie zmienia to
  faktu, że MITM i inspekcja działają
- na `r1` nadal powinieneś widzieć `TlsHandshakeComplete` i `proto=Http`

### Kryterium zaliczenia dla ruchu wychodzącego do Internetu

Test uznaj za zaliczony, jeśli:

- `h2` widzi certyfikat z `issuer` ustawionym na firewall, a nie na publiczny CA
- odpowiedzi z `sha256.badssl.com`, `www.howsmyssl.com` albo `tls.peet.ws`
  wracają poprawnie po HTTPS
- `r1` loguje handshake MITM i klasyfikację `proto=Http`

## Ruch przychodzący

Ważny niuans implementacji:

- bez wgranego certyfikatu serwera dla `192.168.20.10:443` firewall i tak
  przechwyci TLS na `443`
- dopiero po rejestracji certyfikatu przypiętego do `bindAddress/bindPort`
  runtime przechodzi w dedykowany tryb inbound i zaczyna emitować eventy
  `InboundTls...`

Dlatego blok przychodzący ma dwa etapy:

1. ruch `h1 -> h2` bez dedykowanego certyfikatu inbound
2. ruch `h1 -> h2` po wgraniu certyfikatu inbound dla `192.168.20.10:443`

### 1. Upewnij się, że nie masz już starego certyfikatu inbound dla `h2`

Na `r1`:

```bash
python3 - <<'PY'
import json
path = '/resources/backend/data/json-db/firewall_certificates.json'
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)
hits = [
    item for item in data['items']
    if item.get('bindAddress') == '192.168.20.10' and item.get('bindPort') == 443
]
print(hits)
PY
```

Oczekiwany wynik przed testem bazowym:

- `[]`

Jeśli wynik nie jest pusty, ten bind address jest już zajęty przez stary test i
etap bazowy nie pokaże różnicy między trybem zwykłym a inbound.

### 2. Uruchom serwer TLS na `h2`

Na `h2`:

```bash
mkdir -p /tmp/ssl-in
cd /tmp/ssl-in

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout h2-origin.key \
  -out h2-origin.crt \
  -days 7 \
  -subj '/CN=h2-origin.lab'

openssl x509 -in h2-origin.crt -noout -subject -issuer -fingerprint -sha256

sudo openssl s_server -accept 443 -cert h2-origin.crt -key h2-origin.key -www
```

Ten serwer zostaw uruchomiony.

### 3. Test bazowy: `h1 -> h2` bez dedykowanego certyfikatu inbound

Na `h1`:

```bash
echo | openssl s_client \
  -connect 192.168.20.10:443 \
  -servername h2-firewall.lab \
  -showcerts 2>/dev/null | \
openssl x509 -noout -subject -issuer -fingerprint -sha256
```

Oczekiwany wynik:

- `subject` będzie oparty o SNI `h2-firewall.lab`
- `issuer` będzie z firewalla, typowo `RaptorGate Untrust CA`
- w logach `r1` zobaczysz raczej `TlsInterceptStarted`, a nie
  `InboundTlsInterceptStarted`

To pokazuje zwykłe przechwycenie TLS na `443`, ale jeszcze nie dedykowany tryb
inbound oparty o statyczny certyfikat serwera.

### 4. Przygotuj certyfikat inbound do załadowania na `r1`

Na `r1`:

```bash
mkdir -p /tmp/ssl-inbound-fw
cd /tmp/ssl-inbound-fw

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout fw-h2.key \
  -out fw-h2.crt \
  -days 7 \
  -subj '/CN=h2-firewall.lab'

openssl x509 -in fw-h2.crt -noout -subject -issuer -fingerprint -sha256
```

Zapisz sobie fingerprint z tego polecenia. Za chwilę klient na `h1` powinien
zobaczyć dokładnie ten sam fingerprint.

### 5. Wygeneruj token administracyjny do backendu na `r1`

Na `r1`:

```bash
cd /resources/backend

export TOKEN=$(./bun -e "const jwt=require('./node_modules/jsonwebtoken'); console.log(jwt.sign({sub:'00000000-0000-4000-8000-000000000001',username:'admin'}, 'development-jwt-secret-change-me-1234567890', {expiresIn:'60m'}));")

echo "$TOKEN"
```

To używa devowego `JWT_SECRET` z serwisu Vagrant i konta `admin` istniejącego
w plikach JSON backendu.

### 6. Wgraj certyfikat inbound dla `192.168.20.10:443`

Na `r1`:

```bash
python3 - <<'PY'
import json
import os
import ssl
import urllib.request

token = os.environ['TOKEN']

payload = {
    'certificatePem': open('/tmp/ssl-inbound-fw/fw-h2.crt', 'r', encoding='utf-8').read(),
    'privateKeyPem': open('/tmp/ssl-inbound-fw/fw-h2.key', 'r', encoding='utf-8').read(),
    'bindAddress': '192.168.20.10',
    'bindPort': 443,
    'inspectionBypass': False,
    'isActive': True,
}

req = urllib.request.Request(
    'https://127.0.0.1:3000/ssl/server-certificates',
    data=json.dumps(payload).encode('utf-8'),
    headers={
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    },
    method='POST',
)

ctx = ssl._create_unverified_context()
with urllib.request.urlopen(req, context=ctx) as resp:
    print(resp.read().decode())
PY
```

Oczekiwany wynik:

- backend zwraca odpowiedź `201`
- payload zawiera `bindAddress=192.168.20.10` i fingerprint wgranego certyfikatu

### 7. Test właściwy: `h1 -> h2` po wgraniu certyfikatu inbound

Na `h1`:

```bash
echo | openssl s_client \
  -connect 192.168.20.10:443 \
  -servername h2-firewall.lab \
  -showcerts 2>/dev/null | \
openssl x509 -noout -subject -issuer -fingerprint -sha256
```

Oczekiwany wynik:

- fingerprint powinien być identyczny jak fingerprint `fw-h2.crt` z `r1`
- `issuer` i `subject` powinny odpowiadać dokładnie certyfikatowi wgranemu
  na firewall
- to nie powinien już być certyfikat wystawiony przez `RaptorGate Untrust CA`

### 8. Wymuś HTTP wewnątrz TLS po stronie przychodzącej

Na `h1`:

```bash
printf 'GET / HTTP/1.1\r\nHost: h2-firewall.lab\r\nConnection: close\r\n\r\n' | \
openssl s_client \
  -connect 192.168.20.10:443 \
  -servername h2-firewall.lab \
  -quiet
```

Oczekiwany wynik:

- odpowiedź z `openssl s_server -www` działającego na `h2`
- handshake może zgłosić brak zaufania do self-signed certyfikatu, ale ruch ma
  przejść

### 9. Potwierdź, że runtime wszedł w tryb inbound

Na `r1` w logach powinny pojawić się wpisy podobne do:

- `InboundTlsInterceptStarted`
- `InboundTlsHandshakeComplete`
- `Decrypted traffic classified`

Najważniejsza różnica względem etapu bazowego:

- przed uploadem widziałeś `TlsInterceptStarted`
- po uploadzie powinieneś widzieć `InboundTlsInterceptStarted`

### Kryterium zaliczenia dla ruchu przychodzącego

Test uznaj za zaliczony, jeśli:

- przed uploadem klient widzi certyfikat wystawiony przez firewall
  (`RaptorGate Untrust CA` albo `RaptorGate CA`)
- po uploadzie klient widzi dokładnie certyfikat, który wgrałeś dla
  `192.168.20.10:443`
- logi na `r1` przełączają się z `Tls...` na `InboundTls...`
- połączenie `h1 -> h2` nadal zwraca odpowiedź HTTP

## Uwagi praktyczne

- W testach używam `openssl s_server -www`, bo to najprostszy serwer HTTPS do
  odpalenia bez dodatkowych pakietów.
- Dla self-signed certyfikatów ostrzeżenie o niezaufanym issuerze jest
  normalne i nie oznacza, że inspekcja nie działa.
- W testach labowych z lokalnym self-signed upstream dla ruchu wychodzącego
  normalnym wynikiem jest `RaptorGate Untrust CA`.
- Upload certyfikatu inbound jest trwały. Ponowne wgranie certyfikatu dla
  tego samego `bindAddress:bindPort` zastąpi poprzedni wpis.

## Opcjonalny cleanup po teście inbound

Jeśli chcesz powtórzyć test inbound od zera dla `192.168.20.10:443`, na `r1`
możesz usunąć wpis z backendu i odpowiadające mu pliki klucza z PKI:

```bash
export KEYREF=$(python3 - <<'PY'
import json

path = '/resources/backend/data/json-db/firewall_certificates.json'
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)

target = None
rest = []
for item in data['items']:
    if item.get('bindAddress') == '192.168.20.10' and item.get('bindPort') == 443:
        target = item
    else:
        rest.append(item)

data['items'] = rest

with open(path, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2)
    f.write('\n')

print(target['privateKeyRef'] if target else '')
PY
)

sudo rm -f \
  "/var/lib/raptorgate/pki/server_keys/${KEYREF}.key.enc" \
  "/var/lib/raptorgate/pki/server_keys/${KEYREF}.meta.json"

sudo systemctl restart backend ngfw
```

Po cleanupie komenda sprawdzająca z sekcji ruchu przychodzącego powinna znowu
zwrócić pustą listę `[]`.
