# NAT Rules — configi testowe Vagrant (h1 / h2)

Zrodla:
- `frontend/src/pages/NatRules.tsx`
- `frontend/src/components/nat/NatRuleForm.tsx`
- `frontend/src/types/nat/NatRule.ts`
- `backend/src/presentation/dtos/create-nat-rule.dto.ts`
- `backend/src/infrastructure/persistence/schemas/nat-rules.schema.ts`
- `crates/raptorgate/src/nat/config.rs`
- `crates/raptorgate/src/nat/engine.rs`
- `vagrant/vagrantfile`

Topologia:
- h1: `192.168.10.10` (intnet1)
- h2: `192.168.20.10` (intnet2) + HTTP na `8080`
- r1: `192.168.10.254` / `192.168.20.254`
- interfejsy r1: `eth1` (h1), `eth2` (h2)

## Opcje w NAT Rules (UI/API)

Wspolne pola:
- `isActive`: bool
- `priority`: 1..100 (mniejsze = wyzszy priorytet)
- `protocol`: `NAT_PROTOCOL_ALL|NAT_PROTOCOL_TCP|NAT_PROTOCOL_UDP|NAT_PROTOCOL_ICMP`
- `inInterface`, `outInterface`: string lub null
- `inZone`, `outZone`: string lub null
- `matchSrcPortMin/Max`, `matchDstPortMin/Max`: 1..65535, oba naraz lub oba puste

Akcje (action):
- **SNAT**: `srcCidr`, `translatedIp`, opcjonalnie `srcPortMin/Max`
- **DNAT**: `dstCidr`, `translatedIp`, opcjonalnie `translatedPort`
- **PAT**: `dstIp`, `dstPort`, `translatedIp`, `translatedPort`
- **MASQUERADE**: wymaga `outInterface`, opcjonalnie `srcCidr`, `srcPortMin/Max`

Walidacje:
- porty 1..65535
- `match*PortMin/Max` musza byc ustawione razem
- `srcPortMin/Max` musza byc ustawione razem
- `masquerade` wymaga `outInterface`

## Testy

### 1) PAT — port forward 80 -> 8080 (h2 http)

Config:
```json
{
  "isActive": true,
  "priority": 10,
  "protocol": "NAT_PROTOCOL_TCP",
  "inInterface": "eth1",
  "outInterface": "eth2",
  "action": {
    "$case": "pat",
    "pat": {
      "dstIp": "192.168.20.201",
      "dstPort": 80,
      "translatedIp": "192.168.20.10",
      "translatedPort": 8080
    }
  }
}
```

Test (h1):
```bash
curl http://192.168.20.201/api/ping
```

Expected:
- trafia na h2:8080, dostajesz `{"status":"ok"}`

---

### 2) DNAT — bez translatedPort (port zachowany)

Config:
```json
{
  "isActive": true,
  "priority": 10,
  "protocol": "NAT_PROTOCOL_TCP",
  "inInterface": "eth1",
  "action": {
    "$case": "dnat",
    "dnat": {
      "dstCidr": "192.168.20.202/32",
      "translatedIp": "192.168.20.10"
    }
  }
}
```

Test (h1):
```bash
curl http://192.168.20.202:8080/api/ping
```

Expected:
- DNAT do h2, port 8080 zachowany

---

### 3) DNAT — z translatedPort (80 -> 8080)

Config:
```json
{
  "isActive": true,
  "priority": 10,
  "protocol": "NAT_PROTOCOL_TCP",
  "inInterface": "eth1",
  "matchDstPortMin": 80,
  "matchDstPortMax": 80,
  "action": {
    "$case": "dnat",
    "dnat": {
      "dstCidr": "192.168.20.203/32",
      "translatedIp": "192.168.20.10",
      "translatedPort": 8080
    }
  }
}
```

Test (h1):
```bash
curl http://192.168.20.203/api/ping
```

Expected:
- NAT port 80 -> 8080, dostajesz odpowiedz z h2

---

### 4) SNAT — zmiana source IP

Config:
```json
{
  "isActive": true,
  "priority": 10,
  "protocol": "NAT_PROTOCOL_ALL",
  "outInterface": "eth2",
  "action": {
    "$case": "snat",
    "snat": {
      "srcCidr": "192.168.10.0/24",
      "translatedIp": "192.168.20.254"
    }
  }
}
```

Test (h1):
```bash
curl http://192.168.20.10:8080/api/whoami
```

Expected:
- na h2 source IP = `192.168.20.254` (sprawdz tcpdump)

---

### 5) MASQUERADE — dynamiczny SNAT

Config:
```json
{
  "isActive": true,
  "priority": 10,
  "protocol": "NAT_PROTOCOL_ALL",
  "outInterface": "eth2",
  "action": {
    "$case": "masquerade",
    "masquerade": {}
  }
}
```

Test (h1):
```bash
curl http://192.168.20.10:8080/
```

Expected:
- source IP na h2 = IP r1 na `eth2` (192.168.20.254)

---

### 6) Protocol filter

Config (TCP):
```json
{
  "isActive": true,
  "priority": 10,
  "protocol": "NAT_PROTOCOL_TCP",
  "inInterface": "eth1",
  "action": {
    "$case": "dnat",
    "dnat": {
      "dstCidr": "192.168.20.204/32",
      "translatedIp": "192.168.20.10"
    }
  }
}
```

Test:
```bash
curl http://192.168.20.204:8080/api/ping
```

Expected:
- TCP dziala, UDP/ICMP nie beda matchowac tej reguly

---

### 7) Port range match

Config:
```json
{
  "isActive": true,
  "priority": 10,
  "protocol": "NAT_PROTOCOL_TCP",
  "matchDstPortMin": 8080,
  "matchDstPortMax": 8080,
  "action": {
    "$case": "dnat",
    "dnat": {
      "dstCidr": "192.168.20.205/32",
      "translatedIp": "192.168.20.10"
    }
  }
}
```

Test:
```bash
curl http://192.168.20.205:8080/api/ping
curl http://192.168.20.205:8081/api/ping
```

Expected:
- 8080 matchuje, 8081 nie

---

### 8) inInterface/outInterface filter

Config:
```json
{
  "isActive": true,
  "priority": 10,
  "protocol": "NAT_PROTOCOL_TCP",
  "inInterface": "eth1",
  "action": {
    "$case": "dnat",
    "dnat": {
      "dstCidr": "192.168.20.206/32",
      "translatedIp": "192.168.20.10"
    }
  }
}
```

Test:
```bash
vagrant ssh h1 -c "curl http://192.168.20.206:8080/api/ping"
vagrant ssh h2 -c "curl http://192.168.20.206:8080/api/ping"
```

Expected:
- z h1 match (eth1)
- z h2 brak NAT

---

### 9) isActive = false

Config: dowolna regule z `isActive:false`.

Expected:
- reguly nie stosuje

---

### 10) Priority

Config A (priority 5) i Config B (priority 20) dla tego samego matcha.

Expected:
- priorytet nizszy wygrywa

## Jak aplikowac

UI: `NAT Rules` -> `New NAT Rule` / `Edit`.

API:
```bash
curl -X POST https://192.168.56.254:3000/nat \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d @/tmp/nat_rule.json
```

## Weryfikacja

Na h2:
```bash
sudo tcpdump -ni eth1 host 192.168.20.10
```

Na r1:
```bash
journalctl -u ngfw -f
```

## Uwagi

- DNAT/PAT dzialaja w PREROUTING.
- SNAT/MASQUERADE dzialaja w POSTROUTING.
- MASQUERADE wymaga `outInterface`.
- `match*PortMin/Max` musza byc ustawione razem.
