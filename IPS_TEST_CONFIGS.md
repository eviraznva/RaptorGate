# IPS Test Configurations — Vagrant (h1 / h2)

Analyzed from:
- `frontend/src/types/ipsConfig/IpsConfig.ts`
- `frontend/src/components/ips/tabs/*`
- `backend/src/presentation/dtos/update-ips-config.dto.ts`
- `crates/raptorgate/src/data_plane/ips/ips.rs`
- `vagrant/vagrantfile`, `vagrant/scripts/h2-http-server.py`

---

## Topology

```
  h1 (192.168.10.10)  <--intnet1-->  r1 (NGFW + backend + frontend)  <--intnet2-->  h2 (192.168.20.10)
                                      192.168.10.254 / 192.168.20.254
```

- **h1**: postfix + dovecot (SMTP/25, IMAP/143), iperf3 client
- **h2**: python HTTP server on port 8080 (`/`, `/api/ping`, `/api/whoami`), iperf3 server
- **r1**: NGFW with IPS inspection on forwarded traffic + TLS MITM proxy on 8443

---

## IPS Config Structure

```typescript
interface IpsConfig {
  general:   { enabled: boolean };
  detection: { enabled: boolean, maxPayloadBytes: number, maxMatchesPerPacket: number };
  signatures: IpsSignatureConfig[];
}

interface IpsSignatureConfig {
  id: string; name: string; enabled: boolean; category: string;
  pattern: string;
  matchType: "literal" | "regex";
  patternEncoding: "text" | "hex";
  caseInsensitive: boolean;
  severity: "info" | "low" | "medium" | "high" | "critical";
  action: "alert" | "block";
  appProtocols: ("http"|"tls"|"dns"|"ssh"|"ftp"|"smtp"|"rdp"|"smb"|"quic"|"unknown")[];
  srcPorts: number[];   // empty = all
  dstPorts: number[];   // empty = all
}
```

Backend persistence: `backend/data/json-db/ips_configuration.json` + `ips_signatures.json`.

---

## Test Cases

### 1. IPS completely OFF

**Config:**
```json
{
  "general": { "enabled": false },
  "detection": { "enabled": false, "maxPayloadBytes": 4096, "maxMatchesPerPacket": 8 },
  "signatures": []
}
```

**Test from h1:**
```bash
curl http://192.168.20.10:8080/api/whoami
curl -d "cmd=UNION SELECT 1" http://192.168.20.10:8080/api/ping
```

**Expected:** All requests succeed (HTTP 200). No IPS events in VictoriaLogs / firewall log.

---

### 2. IPS ON, detection OFF

**Config:**
```json
{
  "general": { "enabled": true },
  "detection": { "enabled": false, "maxPayloadBytes": 4096, "maxMatchesPerPacket": 8 },
  "signatures": [
    {
      "id": "sig-001", "name": "SQLi", "enabled": true, "category": "sqli",
      "pattern": "(?i)union\\s+select", "matchType": "regex", "patternEncoding": "text",
      "caseInsensitive": false, "severity": "high", "action": "block",
      "appProtocols": ["http"], "srcPorts": [], "dstPorts": [80, 8080]
    }
  ]
}
```

**Test:** same as case 1.

**Expected:** All requests succeed. Detection toggle = false → engine short-circuits to `Allow` before signature matching.

---

### 3. Regex block signature on HTTP dst port 8080

**Config:**
```json
{
  "general": { "enabled": true },
  "detection": { "enabled": true, "maxPayloadBytes": 8192, "maxMatchesPerPacket": 10 },
  "signatures": [
    {
      "id": "sig-sqli-01", "name": "SQLi Block", "enabled": true, "category": "sqli",
      "pattern": "(?i)union\\s+select", "matchType": "regex", "patternEncoding": "text",
      "caseInsensitive": false, "severity": "high", "action": "block",
      "appProtocols": ["http"], "srcPorts": [], "dstPorts": [8080]
    }
  ]
}
```

**Test from h1:**
```bash
curl -d "q=UNION SELECT 1" http://192.168.20.10:8080/api/ping
curl -d "q=normal" http://192.168.20.10:8080/api/ping
```

**Expected:**
- First curl → connection blocked by NGFW (RST or timeout). `ips.signature.blocked` event in firewall log with `signature_name=SQLi Block`.
- Second curl → HTTP 200, no event.

---

### 4. Regex alert signature (no block)

**Config:**
```json
{
  "general": { "enabled": true },
  "detection": { "enabled": true, "maxPayloadBytes": 8192, "maxMatchesPerPacket": 10 },
  "signatures": [
    {
      "id": "sig-ua-01", "name": "Curl UA", "enabled": true, "category": "recon",
      "pattern": "(?i)curl/", "matchType": "regex", "patternEncoding": "text",
      "caseInsensitive": false, "severity": "low", "action": "alert",
      "appProtocols": ["http"], "srcPorts": [], "dstPorts": []
    }
  ]
}
```

**Test from h1:**
```bash
curl -A "curl/8.0.1" http://192.168.20.10:8080/api/whoami
wget -qO- http://192.168.20.10:8080/api/whoami
```

**Expected:**
- curl request → HTTP 200 succeeds (action = alert, not block). `ips.signature.alert` event logged.
- wget request → HTTP 200, no IPS event (pattern does not match).

---

### 5. Literal match (Aho-Corasick, faster than regex)

**Config:**
```json
{
  "general": { "enabled": true },
  "detection": { "enabled": true, "maxPayloadBytes": 8192, "maxMatchesPerPacket": 10 },
  "signatures": [
    {
      "id": "sig-lit-01", "name": "Literal SQLi", "enabled": true, "category": "sqli",
      "pattern": "UNION SELECT", "matchType": "literal", "patternEncoding": "text",
      "caseInsensitive": false, "severity": "high", "action": "block",
      "appProtocols": ["http"], "srcPorts": [], "dstPorts": [8080]
    }
  ]
}
```

**Test from h1:**
```bash
curl -d "q=UNION SELECT 1" http://192.168.20.10:8080/api/ping
curl -d "q=union select 1" http://192.168.20.10:8080/api/ping
```

**Expected:**
- First → blocked (exact literal match).
- Second → allowed (case sensitive literal does not match lowercase).

---

### 6. Case-insensitive literal match

**Config:**
```json
{
  "general": { "enabled": true },
  "detection": { "enabled": true, "maxPayloadBytes": 8192, "maxMatchesPerPacket": 10 },
  "signatures": [
    {
      "id": "sig-lit-ci-01", "name": "CI SQLi", "enabled": true, "category": "sqli",
      "pattern": "union select", "matchType": "literal", "patternEncoding": "text",
      "caseInsensitive": true, "severity": "high", "action": "block",
      "appProtocols": ["http"], "srcPorts": [], "dstPorts": [8080]
    }
  ]
}
```

**Test:**
```bash
curl -d "q=UNION SELECT 1" http://192.168.20.10:8080/api/ping
curl -d "q=UnIoN SeLeCt 1" http://192.168.20.10:8080/api/ping
```

**Expected:** Both blocked. Engine uses `AhoCorasickBuilder::ascii_case_insensitive(true)`.

**Backend validation:** `patternEncoding=hex` + `caseInsensitive=true` → rejected by Zod refine.

---

### 7. Hex-encoded literal pattern

**Config:**
```json
{
  "general": { "enabled": true },
  "detection": { "enabled": true, "maxPayloadBytes": 8192, "maxMatchesPerPacket": 10 },
  "signatures": [
    {
      "id": "sig-hex-01", "name": "NOP sled", "enabled": true, "category": "exploit",
      "pattern": "90909090", "matchType": "literal", "patternEncoding": "hex",
      "caseInsensitive": false, "severity": "critical", "action": "block",
      "appProtocols": [], "srcPorts": [], "dstPorts": []
    }
  ]
}
```

**Test from h1 (send raw bytes):**
```bash
python3 -c "
import socket
s = socket.socket()
s.connect(('192.168.20.10', 8080))
s.send(b'\x90\x90\x90\x90GET / HTTP/1.1\r\nHost: x\r\n\r\n')
print(s.recv(4096))
"
```

**Expected:** Connection blocked. Engine decodes hex pattern to `\x90\x90\x90\x90` before Aho-Corasick build.

**Backend validation:** `patternEncoding=hex` + `matchType=regex` → rejected by Zod refine.

---

### 8. maxPayloadBytes limit

**Config:**
```json
{
  "general": { "enabled": true },
  "detection": { "enabled": true, "maxPayloadBytes": 8, "maxMatchesPerPacket": 10 },
  "signatures": [
    {
      "id": "sig-long-01", "name": "Long SQLi", "enabled": true, "category": "sqli",
      "pattern": "UNION SELECT", "matchType": "literal", "patternEncoding": "text",
      "caseInsensitive": false, "severity": "high", "action": "block",
      "appProtocols": ["http"], "srcPorts": [], "dstPorts": [8080]
    }
  ]
}
```

**Test:**
```bash
# Pattern starts at byte 0, within 8-byte window
curl -d "UNION SELECT 1" http://192.168.20.10:8080/api/ping

# Pattern starts after 8 bytes, truncated
curl -d "12345678UNION SELECT 1" http://192.168.20.10:8080/api/ping
```

**Expected:**
- First → blocked (pattern in first 8 bytes).
- Second → allowed (pattern beyond `maxPayloadBytes`, engine slices payload).

---

### 9. maxMatchesPerPacket limit

**Config:**
```json
{
  "general": { "enabled": true },
  "detection": { "enabled": true, "maxPayloadBytes": 8192, "maxMatchesPerPacket": 1 },
  "signatures": [
    {
      "id": "sig-a", "name": "Match A", "enabled": true, "category": "test",
      "pattern": "AAAA", "matchType": "literal", "patternEncoding": "text",
      "caseInsensitive": false, "severity": "low", "action": "alert",
      "appProtocols": [], "srcPorts": [], "dstPorts": []
    },
    {
      "id": "sig-b", "name": "Match B", "enabled": true, "category": "test",
      "pattern": "BBBB", "matchType": "literal", "patternEncoding": "text",
      "caseInsensitive": false, "severity": "low", "action": "block",
      "appProtocols": [], "srcPorts": [], "dstPorts": []
    }
  ]
}
```

**Test:**
```bash
python3 -c "
import socket
s = socket.socket()
s.connect(('192.168.20.10', 8080))
s.send(b'AAAABBBB GET / HTTP/1.1\r\nHost: x\r\n\r\n')
print(s.recv(4096))
"
```

**Expected:** Alert for `AAAA` only (first match). `BBBB` not evaluated because `maxMatchesPerPacket = 1`. No block.

---

### 10. appProtocol filter — SMTP only

**Config:**
```json
{
  "general": { "enabled": true },
  "detection": { "enabled": true, "maxPayloadBytes": 8192, "maxMatchesPerPacket": 10 },
  "signatures": [
    {
      "id": "sig-smtp-01", "name": "SMTP probe", "enabled": true, "category": "recon",
      "pattern": "VRFY", "matchType": "literal", "patternEncoding": "text",
      "caseInsensitive": false, "severity": "medium", "action": "alert",
      "appProtocols": ["smtp"], "srcPorts": [], "dstPorts": [25]
    }
  ]
}
```

**Test from h2 to h1:**
```bash
# Requires DPI to identify SMTP; r1 runs SMTP proxy/inspector
telnet 192.168.10.10 25
VRFY root
```

Or via swaks:
```bash
swaks --to user1@test.local --server 192.168.10.10 --quit-after RCPT
```

**Expected:** If DPI tags flow as `AppProto::Smtp`, VRFY triggers alert. If DPI cannot identify protocol (no TLS/SMTP ALPN/plain-text logic), flow allowed → no event.

**Note:** DPI SMTP detection relies on port 25 heuristics or STARTTLS. If DPI misses it, no match. This tests both protocol classification accuracy and IPS filtering.

---

### 11. srcPorts filter

**Config:**
```json
{
  "general": { "enabled": true },
  "detection": { "enabled": true, "maxPayloadBytes": 8192, "maxMatchesPerPacket": 10 },
  "signatures": [
    {
      "id": "sig-src-01", "name": "High-port SQLi", "enabled": true, "category": "sqli",
      "pattern": "UNION SELECT", "matchType": "literal", "patternEncoding": "text",
      "caseInsensitive": false, "severity": "high", "action": "block",
      "appProtocols": ["http"], "srcPorts": [54321], "dstPorts": [8080]
    }
  ]
}
```

**Test from h1:**
```bash
# curl uses ephemeral source port (unlikely 54321)
curl -d "UNION SELECT 1" http://192.168.20.10:8080/api/ping

# Force source port with nc (linux)
nc -p 54321 192.168.20.10 8080 <<'EOF'
POST /api/ping HTTP/1.1
Host: 192.168.20.10:8080
Content-Length: 16

UNION SELECT 1
EOF
```

**Expected:**
- curl → allowed (src port not 54321).
- nc with `-p 54321` → blocked.

**Note:** `nc -p` requires OpenBSD netcat; verify with `nc -h`. May need `ncat --source-port 54321` instead.

---

### 12. Decrypted TLS inspection (MITM proxy)

**Config on r1:**
- Ensure `ssl_bypass_list` does NOT contain `192.168.20.10`
- TLS inspection enabled in zones/zone_pairs so traffic h1→h2 is decrypted

**IPS Config:**
```json
{
  "general": { "enabled": true },
  "detection": { "enabled": true, "maxPayloadBytes": 8192, "maxMatchesPerPacket": 10 },
  "signatures": [
    {
      "id": "sig-tls-01", "name": "Secret keyword", "enabled": true, "category": "data-loss",
      "pattern": "SECRET_TOKEN", "matchType": "literal", "patternEncoding": "text",
      "caseInsensitive": false, "severity": "critical", "action": "block",
      "appProtocols": ["tls"], "srcPorts": [], "dstPorts": [443]
    }
  ]
}
```

**Test from h1:**
```bash
# h2 does not serve HTTPS on 443, but r1 MITM proxy terminates TLS locally on 8443.
# If you have an HTTPS endpoint through r1, test with:
curl -k -d "SECRET_TOKEN=123" https://<tls-endpoint>/api/data
```

**Expected:** Decrypted payload inspected by `inspect_decrypted()`. If `SECRET_TOKEN` present in HTTP body inside TLS → blocked. `DecryptedIpsMatch` event emitted with `blocked=true`.

**Verification in logs:** Search VictoriaLogs for `source=IPS` + `mode=Decrypted`.

---

### 13. Signature disabled hot-swap test

**Config (initial):**
Signature enabled = true, action = block.

Apply config, verify block works.

**Config (updated via UI / API):**
Same signature, `enabled = false`.

**Test:**
```bash
curl -d "q=UNION SELECT 1" http://192.168.20.10:8080/api/ping
```

**Expected:** Allowed. Engine hot-swaps config via `update_config()` → `CompiledIpsState` rebuilt without disabled signatures.

---

## How to apply configs

### Method A — REST API directly
```bash
# On r1 or from host with access to 192.168.56.254:3000
TOKEN=$(curl -s -X POST https://192.168.56.254:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.data.accessToken')

curl -X PUT https://192.168.56.254:3000/ips-config \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d @/tmp/ips_test_config.json
```

### Method B — Frontend
1. Open `https://192.168.56.254/dashboard/ips`
2. Switch tabs: General / Detection / Signatures
3. Edit fields, click **APPLY**

### Method C — Edit raw JSON-DB
```bash
# On r1
sudo systemctl stop backend
vim /resources/backend/data/json-db/ips_configuration.json
vim /resources/backend/data/json-db/ips_signatures.json
sudo systemctl start backend
```

---

## Verification commands

### Check firewall events
```bash
# VictoriaLogs query (from r1 or host)
curl -s "http://192.168.56.254:9428/select/logsql/query" \
  -d 'query=source:IPS | fields _time, signature_name, action, blocked, src_ip, dst_ip'
```

### Live tail firewall log
```bash
# On r1
journalctl -u ngfw -f
```

### Packet capture on r1
```bash
sudo tcpdump -i eth1 -nn -A port 8080 or port 25
sudo tcpdump -i eth2 -nn -A port 8080 or port 25
```

### Direct IPS unit tests (Rust)
```bash
cd /home/marek/RaptorGate/crates/raptorgate
cargo test ips:: -- --nocapture
```

---

## Matrix summary

| # | General | Detection | Signature config | Test command h1→h2 or h2→h1 | Expected |
|---|---------|-----------|------------------|------------------------------|----------|
| 1 | OFF | OFF | — | any curl | Allow, no logs |
| 2 | ON | OFF | block regex | curl with payload | Allow (detection off) |
| 3 | ON | ON | block regex HTTP/8080 | curl -d "UNION SELECT" | Block + log |
| 4 | ON | ON | alert regex curl/ | curl -A curl/8 | Allow + alert log |
| 5 | ON | ON | literal block | curl -d "UNION SELECT" | Block |
| 6 | ON | ON | literal CI block | curl -d "union select" | Block |
| 7 | ON | ON | hex literal block | python send \x90\x90\x90\x90 | Block |
| 8 | ON | ON | maxPayloadBytes=8 | long prefix payload | Allow (truncated) |
| 9 | ON | ON | maxMatches=1 | multi-pattern payload | Alert first, skip rest |
| 10 | ON | ON | alert SMTP/25 | swaks / telnet VRFY | Alert if DPI=Smtp |
| 11 | ON | ON | srcPorts=[54321] | curl vs nc -p 54321 | Block only on src 54321 |
| 12 | ON | ON | block TLS/443 | curl -k https + secret | Block decrypted |
| 13 | ON | ON | hot-disable sig | curl after disable | Allow |

---

## Caveats

- `appProtocols` filter requires DPI to tag flow. If DPI misses protocol, IPS allows.
- `tls` appProtocol matches **decrypted** payloads only (MITM relay); encrypted raw TLS bytes are not regex-searched.
- `srcPorts` with curl is hard to pin; use `ncat --source-port` for deterministic testing.
- Hex patterns must have even length and valid hex chars; backend enforces this.
- `caseInsensitive` allowed only for `literal` + `text`; backend rejects hex+CI.
