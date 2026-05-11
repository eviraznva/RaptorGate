# DNS inspection — configi testowe dla Vagrant

Zakładka DNS edytuje cały `DnsInspectionConfig`, wysyłany jako `PUT /dns-inspection`.

Źródła:
- `frontend/src/types/dnsInspection/DnsInspectionConfig.ts`
- `frontend/src/components/dns/tabs/*.tsx`
- `frontend/src/components/dns/validation.ts`
- `frontend/src/services/dnsInspection.ts`
- `vagrant/vagrantfile`

Hosty Vagrant:
- `h1`: `192.168.10.10`
- `h2`: `192.168.20.10`
- `r1 h1-side`: `192.168.10.254`
- `r1 h2-side`: `192.168.20.254`
- DNS na h1/h2: `8.8.8.8`

## Opcje

### General

```json
"general": {
  "enabled": true
}
```

- `enabled`: master switch modułu DNS inspection.

### Blocklist

```json
"blocklist": {
  "enabled": true,
  "domains": ["example.com", "*.tracking.local"]
}
```

- `enabled`: blocklist on/off.
- `domains`: lista domen, jedna per linia w UI.

### DNS Tunneling

```json
"dnsTunneling": {
  "enabled": true,
  "maxLabelLength": 40,
  "entropyThreshold": 3.5,
  "windowSeconds": 60,
  "maxQueriesPerDomain": 100,
  "maxUniqueSubdomains": 20,
  "ignoreDomains": [],
  "alertThreshold": 0.6,
  "blockThreshold": 0.85
}
```

- `enabled`: detektor on/off.
- `maxLabelLength`: maks długość DNS labela.
- `entropyThreshold`: próg entropii.
- `windowSeconds`: okno agregacji.
- `maxQueriesPerDomain`: max zapytań na domenę w oknie.
- `maxUniqueSubdomains`: max unikalnych subdomen.
- `ignoreDomains`: domeny pomijane.
- `alertThreshold`: próg alertu `0..1`.
- `blockThreshold`: próg blokady `0..1`.
- Frontend wymaga `alertThreshold <= blockThreshold`.

### DNSSEC

```json
"dnssec": {
  "enabled": true,
  "maxLookupsPerPacket": 1,
  "defaultOnResolverFailure": "allow",
  "resolver": {
    "primary": { "address": "8.8.8.8", "port": 53 },
    "secondary": { "address": "1.1.1.1", "port": 53 },
    "transport": "udpWithTcpFallback",
    "timeoutMs": 2000,
    "retries": 1
  },
  "cache": {
    "enabled": true,
    "maxEntries": 4096,
    "ttlSeconds": {
      "secure": 300,
      "insecure": 300,
      "bogus": 60,
      "failure": 15
    }
  }
}
```

- `enabled`: DNSSEC on/off.
- `maxLookupsPerPacket`: limit lookupów na pakiet.
- `defaultOnResolverFailure`: `allow`, `alert`, `block`.
- `resolver.primary.address`: wymagany IP, nie hostname.
- `resolver.secondary.address`: opcjonalny IP albo puste.
- `transport`: `udp`, `tcp`, `udpWithTcpFallback`.
- `timeoutMs`: timeout resolvera.
- `retries`: liczba retry.
- `cache.enabled`: cache on/off.
- `cache.maxEntries`: limit wpisów.
- `ttlSeconds.secure`: TTL secure.
- `ttlSeconds.insecure`: TTL insecure.
- `ttlSeconds.bogus`: TTL bogus.
- `ttlSeconds.failure`: TTL failure.

## Config 0 — baseline, wszystko off

```json
{
  "general": { "enabled": false },
  "blocklist": { "enabled": false, "domains": [] },
  "dnsTunneling": {
    "enabled": false,
    "maxLabelLength": 40,
    "entropyThreshold": 3.5,
    "windowSeconds": 60,
    "maxQueriesPerDomain": 100,
    "maxUniqueSubdomains": 20,
    "ignoreDomains": [],
    "alertThreshold": 0.6,
    "blockThreshold": 0.85
  },
  "dnssec": {
    "enabled": false,
    "maxLookupsPerPacket": 1,
    "defaultOnResolverFailure": "allow",
    "resolver": {
      "primary": { "address": "8.8.8.8", "port": 53 },
      "secondary": { "address": "", "port": 53 },
      "transport": "udpWithTcpFallback",
      "timeoutMs": 2000,
      "retries": 1
    },
    "cache": {
      "enabled": true,
      "maxEntries": 4096,
      "ttlSeconds": { "secure": 300, "insecure": 300, "bogus": 60, "failure": 15 }
    }
  }
}
```

Test:

```bash
vagrant ssh h1 -c 'dig example.com'
vagrant ssh h2 -c 'dig example.com'
```

## Config 1 — master on, reszta off

Jak Config 0, ale:

```json
"general": { "enabled": true }
```

Test:

```bash
vagrant ssh h1 -c 'dig example.com'
vagrant ssh h2 -c 'dig example.com'
```

## Config 2 — blocklist exact domain

Jak Config 1, ale:

```json
"blocklist": {
  "enabled": true,
  "domains": ["example.com"]
}
```

Test:

```bash
vagrant ssh h1 -c 'dig example.com'
vagrant ssh h2 -c 'dig example.com'
vagrant ssh h1 -c 'dig google.com'
vagrant ssh h2 -c 'dig google.com'
```

Oczekiwane:
- `example.com` blokowane/alarmowane według backend.
- `google.com` przechodzi.

## Config 3 — blocklist wildcard

Jak Config 1, ale:

```json
"blocklist": {
  "enabled": true,
  "domains": ["*.tracking.local"]
}
```

Test:

```bash
vagrant ssh h1 -c 'dig a.tracking.local'
vagrant ssh h2 -c 'dig b.tracking.local'
```

## Config 4 — DNS tunneling, łatwy alert/block

Jak Config 1, ale:

```json
"dnsTunneling": {
  "enabled": true,
  "maxLabelLength": 20,
  "entropyThreshold": 2.5,
  "windowSeconds": 30,
  "maxQueriesPerDomain": 5,
  "maxUniqueSubdomains": 3,
  "ignoreDomains": [],
  "alertThreshold": 0.2,
  "blockThreshold": 0.4
}
```

Test:

```bash
vagrant ssh h1 -c 'for i in 1 2 3 4 5 6 7 8; do dig $(openssl rand -hex 16).tunnel.test; done'
vagrant ssh h2 -c 'for i in 1 2 3 4 5 6 7 8; do dig $(openssl rand -hex 16).tunnel.test; done'
```

Bez `openssl`:

```bash
vagrant ssh h1 -c 'for i in 1 2 3 4 5 6 7 8; do dig abcdefghijklmnopqrstuvwxyz123456$i.tunnel.test; done'
vagrant ssh h2 -c 'for i in 1 2 3 4 5 6 7 8; do dig abcdefghijklmnopqrstuvwxyz123456$i.tunnel.test; done'
```

## Config 5 — DNS tunneling ignoreDomains

Jak Config 4, ale:

```json
"ignoreDomains": ["tunnel.test"]
```

Test:

```bash
vagrant ssh h1 -c 'for i in 1 2 3 4 5 6 7 8; do dig abcdefghijklmnopqrstuvwxyz123456$i.tunnel.test; done'
vagrant ssh h2 -c 'for i in 1 2 3 4 5 6 7 8; do dig abcdefghijklmnopqrstuvwxyz123456$i.tunnel.test; done'
```

Oczekiwane: mniej/brak alertów dla `tunnel.test`.

## Config 6 — DNSSEC UDP

Jak Config 1, ale:

```json
"dnssec": {
  "enabled": true,
  "maxLookupsPerPacket": 1,
  "defaultOnResolverFailure": "allow",
  "resolver": {
    "primary": { "address": "8.8.8.8", "port": 53 },
    "secondary": { "address": "1.1.1.1", "port": 53 },
    "transport": "udp",
    "timeoutMs": 2000,
    "retries": 1
  },
  "cache": {
    "enabled": true,
    "maxEntries": 4096,
    "ttlSeconds": { "secure": 300, "insecure": 300, "bogus": 60, "failure": 15 }
  }
}
```

Test:

```bash
vagrant ssh h1 -c 'dig cloudflare.com'
vagrant ssh h2 -c 'dig cloudflare.com'
```

## Config 7 — DNSSEC TCP

Jak Config 6, ale:

```json
"transport": "tcp"
```

Test:

```bash
vagrant ssh h1 -c 'dig cloudflare.com'
vagrant ssh h2 -c 'dig cloudflare.com'
```

## Config 8 — DNSSEC UDP z fallback TCP

Jak Config 6, ale:

```json
"transport": "udpWithTcpFallback"
```

Test:

```bash
vagrant ssh h1 -c 'dig cloudflare.com'
vagrant ssh h2 -c 'dig cloudflare.com'
```

## Config 9 — DNSSEC resolver failure: allow

Primary celowo nieosiągalny.

Jak Config 1, ale:

```json
"dnssec": {
  "enabled": true,
  "maxLookupsPerPacket": 1,
  "defaultOnResolverFailure": "allow",
  "resolver": {
    "primary": { "address": "192.0.2.1", "port": 53 },
    "secondary": { "address": "", "port": 53 },
    "transport": "udp",
    "timeoutMs": 200,
    "retries": 0
  },
  "cache": {
    "enabled": false,
    "maxEntries": 128,
    "ttlSeconds": { "secure": 5, "insecure": 5, "bogus": 5, "failure": 5 }
  }
}
```

Test:

```bash
vagrant ssh h1 -c 'dig cloudflare.com'
vagrant ssh h2 -c 'dig cloudflare.com'
```

## Config 10 — DNSSEC resolver failure: alert

Jak Config 9, ale:

```json
"defaultOnResolverFailure": "alert"
```

## Config 11 — DNSSEC resolver failure: block

Jak Config 9, ale:

```json
"defaultOnResolverFailure": "block"
```

Oczekiwane:
- `allow`: ruch przechodzi mimo failure.
- `alert`: ruch przechodzi + alert/log.
- `block`: ruch blokowany przy failure.

## Config 12 — DNSSEC cache on/off i krótkie TTL

Jak Config 1, ale:

```json
"dnssec": {
  "enabled": true,
  "maxLookupsPerPacket": 2,
  "defaultOnResolverFailure": "alert",
  "resolver": {
    "primary": { "address": "8.8.8.8", "port": 53 },
    "secondary": { "address": "1.1.1.1", "port": 53 },
    "transport": "udpWithTcpFallback",
    "timeoutMs": 1000,
    "retries": 2
  },
  "cache": {
    "enabled": true,
    "maxEntries": 16,
    "ttlSeconds": { "secure": 10, "insecure": 10, "bogus": 5, "failure": 2 }
  }
}
```

Test:

```bash
vagrant ssh h1 -c 'dig cloudflare.com; dig cloudflare.com'
vagrant ssh h2 -c 'dig cloudflare.com; dig cloudflare.com'
```

Potem ustaw:

```json
"cache": {
  "enabled": false,
  "maxEntries": 16,
  "ttlSeconds": { "secure": 10, "insecure": 10, "bogus": 5, "failure": 2 }
}
```

Powtórz test i porównaj logi/czas.

## Config 13 — walidacja UI/backend

Powinno blokować Apply albo zwrócić błąd:

```json
{
  "general": { "enabled": true },
  "blocklist": { "enabled": false, "domains": [] },
  "dnsTunneling": {
    "enabled": true,
    "maxLabelLength": 40,
    "entropyThreshold": 3.5,
    "windowSeconds": 60,
    "maxQueriesPerDomain": 100,
    "maxUniqueSubdomains": 20,
    "ignoreDomains": [],
    "alertThreshold": 0.9,
    "blockThreshold": 0.2
  },
  "dnssec": {
    "enabled": true,
    "maxLookupsPerPacket": 1,
    "defaultOnResolverFailure": "allow",
    "resolver": {
      "primary": { "address": "", "port": 53 },
      "secondary": { "address": "not-an-ip", "port": 70000 },
      "transport": "udp",
      "timeoutMs": 2000,
      "retries": 1
    },
    "cache": {
      "enabled": true,
      "maxEntries": 4096,
      "ttlSeconds": { "secure": 300, "insecure": 300, "bogus": 60, "failure": 15 }
    }
  }
}
```

Sprawdza:
- brak primary resolver address,
- port poza `1..65535`,
- `alertThreshold > blockThreshold`,
- backend IP validation dla secondary.

## Minimalna macierz

1. Config 0 — master off.
2. Config 1 — master on.
3. Config 2 — blocklist exact.
4. Config 3 — blocklist wildcard.
5. Config 4 — tunneling thresholds trigger.
6. Config 5 — tunneling ignoreDomains.
7. Config 6 — DNSSEC UDP.
8. Config 7 — DNSSEC TCP.
9. Config 8 — DNSSEC UDP fallback.
10. Config 9/10/11 — resolver failure actions.
11. Config 12 — cache + TTL.
12. Config 13 — walidacja.

## Ważne

W DNSSEC `address` musi być IP. `8.8.8.8`, `1.1.1.1`, `192.0.2.1` są OK jako testy. `dns.google` nie przejdzie backend validation.
