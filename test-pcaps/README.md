# test-pcaps — testy IPS end-to-end na prawdziwych pcapach

Pobiera prawdziwe pcapy ataków (malware-traffic-analysis, Wireshark sample
captures, tcpreplay), dostosowuje je do środowiska testowego i odtwarza z h1 do
h2 przez RaptorGate. Sygnatury IPS w `config-import-in-frontend.json` są
wyciągnięte z tych właśnie pcapów.

## Topologia

```
h1 (client)            RaptorGate            h2 (server)
192.168.10.10  ----->  firewall + IPS  ----->  192.168.20.10
                        inspekcja na porcie TCP 18090
```

## Pliki

| Plik | Rola |
|------|------|
| `prepare_pcaps.py` | **Host**: pobiera pcapy → wypakowuje → dostosowuje do h1→h2:18090. Wynik w `generated/`. |
| `replay_generated_pcaps.py` | **h1**: odtwarza payloady z pcapów do h2. Instalowany jako `replay-ips-test-pcaps`. |
| `h2_payload_watch.py` | **h2**: nasłuch, loguje payloady które przeszły IPS. Jako `watch-ips-test-payloads`. |
| `config-import-in-frontend.json` | Snapshot configu z sygnaturami IPS do importu w webui. |
| `generated/` | Gotowe, dostosowane pcapy (gitignore — nie idą do repo). |
| `generate_ips_pcaps.py` | (opcjonalnie) generator syntetycznych pcapów z samego configu, gdy nie chcesz pobierać. |

## Kolejność uruchomienia

### Krok 1 — pobierz i przygotuj pcapy (na hoście)

```bash
python3 test-pcaps/prepare_pcaps.py
```

Robi po kolei:
- pobiera pcapy ze źródeł (zip z malware-traffic-analysis są hasłowane — hasła wpisane w skrypcie),
- wypakowuje (`unzip`/`gzip`),
- wycina dwie grupy pakietów (resztę szumu wyrzuca):
  - **`attack_*.pcap`** — pakiety niosące sygnaturę IPS (po bajtach, z `config-import-in-frontend.json`); mają być **zablokowane**,
  - **`benign_*.pcap`** — czyste requesty HTTP bez sygnatury; mają **przejść** (legit ruch),
- przepisuje zostawione pakiety na trasę **h1 (192.168.10.10) → h2 (192.168.20.10) port 18090** i przelicza sumy kontrolne,
- zapisuje wynik do `test-pcaps/generated/*.pcap` (jeden pakiet = jedno połączenie w replayu).

Wymaga internetu, `unzip` i `gzip` na hoście. Pady pojedynczych źródeł są pomijane (reszta leci dalej).

### Krok 2 — deploy (wkłada gotowe pcapy do h1)

```bash
cd vagrant
./deploy.sh
```

`install_ips_test_pcaps` na końcu deploya:
- **h1**: kopiuje `generated/*.pcap` do `/opt/raptorgate-test-pcaps/generated/` i instaluje `replay-ips-test-pcaps`,
- **h2**: instaluje `watch-ips-test-payloads` + `config-import-in-frontend.json`.

Jeśli `test-pcaps/generated` jest puste, deploy pominie instalację na h1 i przypomni o kroku 1.

### Krok 3 — watcher na h2

```bash
vagrant ssh h2 -c "sudo watch-ips-test-payloads --seconds 60"
```

Nasłuch na 18090, log do `/tmp/raptorgate-ips-watch.log`. Zostaw okno otwarte.

### Krok 4 — import configu w frontendzie

W webui RaptorGate zaimportuj `test-pcaps/config-import-in-frontend.json`
(Config Control → import / apply). To wgrywa sygnatury IPS, które ten test sprawdza.

### Krok 5 — replay z h1

W drugim terminalu, gdy watcher działa:

```bash
vagrant ssh h1 -c "sudo replay-ips-test-pcaps"
```

Wysyła payloady wszystkich pcapów z `/opt/raptorgate-test-pcaps/generated` na `192.168.20.10:18090`.

### Krok 6 — odczyt wyniku

- **Replay (h1)** — każda linia ma `[attack]`/`[benign]` + `OK`/`BAD`, na końcu:
  ```
  ATTACK : N wyslanych, 0 przeszlo (powinno 0)
  BENIGN : M wyslanych, 0 zablokowanych (powinno 0)
  WYNIK: OK — ataki blokowane, legit ruch przepuszczony
  ```
  - `attack` + `result=response` = atak przeszedł → BAD.
  - `benign` + `result=timeout/reset` = legit zablokowany → BAD.
- **Watcher (h2)** — niezależny detektor wycieków ataków:
  - `OK: no forbidden payload observed` → żaden atak nie dotarł ✅
  - `FAILED: observed N forbidden payload(s)` → atak przeszedł ❌ (log)

PASS gdy replay mówi `WYNIK: OK` i watcher `OK`.

## Wymagania

- Host: Python 3, `unzip`, `gzip`, internet.
- h1: `scapy` (`replay_generated_pcaps.py` używa `scapy.all`) — vagrant instaluje `python3-scapy`.
- h2: Python 3 (watcher — tylko stdlib).
