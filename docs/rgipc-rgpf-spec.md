# Specyfikacja `RGIPC/1` i `RGPF/1`

## Status dokumentu

Ten dokument opisuje aktualnie zaimplementowany kontrakt:

- lokalne IPC `RGIPC/1` nad `AF_UNIX/SOCK_STREAM`,
- runtime firewalla oparty o `SyncIpcEndpoint` i `AsyncIpcEndpoint`,
- magazyn rewizji oparty o katalogi `versions/<revision>` i symlink `active`,
- format `RGPF/1`, w którym `policy.bin` przechowuje wiele polityk DSL wraz z priorytetami oraz jeden globalny `default_verdict`,
- kompilację każdej polityki DSL do runtime dopiero podczas ładowania rewizji w firewallu.

## 1. Cel

Podział odpowiedzialności jest następujący:

- backend publikuje rewizję do systemu plików,
- firewall ładuje `active/policy.bin`,
- firewall parsuje `RGPF/1`,
- firewall pobiera z pliku listę polityk DSL,
- firewall kompiluje każdą politykę DSL do runtime dopiero podczas ładowania rewizji,
- przy błędzie nowa rewizja jest odrzucana, a ostatnia poprawna polityka pozostaje aktywna w pamięci.

## 2. Magazyn rewizji

Układ katalogów:

```text
/etc/raptorgate/config/runtime/versions/<revision>/policy.bin
/etc/raptorgate/config/runtime/active -> versions/<revision>
```

Gdzie:

- `<revision>` jest nazwą katalogu będącą liczbą `u64`,
- firewall ładuje zawsze plik `active/policy.bin`,
- firewall dodatkowo sprawdza zgodność:
  - `revision_id` z requestu IPC,
  - `<revision>` z targetu symlinka `active`,
  - `revision_id` z nagłówka `RGPF/1`.

Firewall nie publikuje rewizji i nie modyfikuje symlinka `active`. Jest tylko czytelnikiem magazynu.

## 3. Architektura `RGIPC/1`

### 3.1. Gniazda

Komunikacja lokalna używa dwóch gniazd Unix Domain Socket:

- `rg-synchronous.sock`
- `rg-asynchronous.sock`

### 3.2. Role kanałów

Kanał synchroniczny obsługuje komunikację `REQUEST -> RESPONSE | ERROR`:

- `PING`
- `GET_STATUS`
- `GET_NETWORK_INTERFACES`
- `ACTIVATE_REVISION`

Kanał asynchroniczny obsługuje komunikację zdarzeniową:

- `HEARTBEAT`

### 3.3. Transport

Warstwa transportowa:

- `AF_UNIX`
- `SOCK_STREAM`
- własne ramkowanie na poziomie aplikacji

Granica wiadomości wynika z pola `payload_len`.

## 4. Format ramki `RGIPC/1`

Ramka jest sekwencją pól:

```text
magic
version
kind
flags
opcode
status
request_id
sequence_no
payload_len
payload
```

Typy pól:

```text
magic        : varint
version      : varint
kind         : varint
flags        : varint
opcode       : varint
status       : varint
request_id   : varlong
sequence_no  : varlong
payload_len  : varint
payload      : [payload_len bytes]
```

Wszystkie liczby całkowite w IPC są kodowane jako:

- `varint` dla `u32`,
- `varlong` dla `u64`.

`bool` jest kodowany jako `varint`:

- `0 = false`
- `1 = true`

`string` jest kodowany jako:

- `len : varint`
- `bytes[len]`, UTF-8, bez `NUL`

## 5. Typy wiadomości i statusy IPC

`kind`:

- `1 = EVENT`
- `2 = REQUEST`
- `3 = RESPONSE`
- `4 = ERROR`

`flags`:

- `0x00 = NONE`
- `0x01 = ACK_REQUIRED`
- `0x02 = CRITICAL`
- `0x04 = NO_REPLY`

`opcode`:

- `0x01 = PING`
- `0x02 = GET_STATUS`
- `0x03 = GET_NETWORK_INTERFACES`
- `0x04 = ACTIVATE_REVISION`
- `0x100 = HEARTBEAT`

`status`:

- `0 = OK`
- `1 = ACCEPTED`
- `100 = ERR_BAD_MAGIC`
- `101 = ERR_UNSUPPORTED_VERSION`
- `102 = ERR_BAD_FRAME`
- `103 = ERR_BAD_PAYLOAD_LEN`
- `104 = ERR_UNSUPPORTED_OPCODE`
- `105 = ERR_MALFORMED_PAYLOAD`
- `200 = ERR_INTERNAL`
- `201 = ERR_POLICY_NOT_LOADED`
- `202 = ERR_INTERFACE_ENUM_FAILED`
- `203 = ERR_POLICY_LOAD_FAILED`
- `204 = ERR_POLICY_REVISION_MISMATCH`

## 6. Wiadomości `RGIPC/1`

### 6.1. `PING`

Żądanie:

```text
timestamp_ms : varlong
```

Odpowiedź:

```text
timestamp_ms      : varlong
peer_timestamp_ms : varlong
```

### 6.2. `GET_STATUS`

Żądanie:

- pusty payload

Odpowiedź:

```text
mode               : varint
loaded_revision_id : varlong
policy_hash        : varlong
uptime_sec         : varlong
last_error_code    : varint
```

`mode`:

- `1 = NORMAL`
- `2 = DEGRADED`
- `3 = EMERGENCY`

### 6.3. `GET_NETWORK_INTERFACES`

Żądanie:

- pusty payload

Odpowiedź:

```text
interfaces_count : varint

repeat interfaces_count times:
    name_len     : varint
    name_bytes   : [name_len]
    index        : varint
    is_up        : varint
    mtu          : varint
    mac_len      : varint
    mac_bytes    : [mac_len]
    ip_count     : varint

    repeat ip_count times:
        ip_len   : varint
        ip_bytes : [ip_len]
```

### 6.4. `ACTIVATE_REVISION`

Żądanie:

```text
revision_id : varlong
```

Odpowiedź:

```text
loaded_revision_id : varlong
policy_hash        : varlong
rule_count         : varint
```

Semantyka:

- backend najpierw publikuje nową rewizję do magazynu,
- backend atomowo przełącza symlink `active`,
- backend wysyła `ACTIVATE_REVISION`,
- firewall ładuje `active/policy.bin`,
- firewall sprawdza zgodność rewizji i kompiluje polityki DSL do runtime,
- przy sukcesie aktywuje nową rewizję,
- przy błędzie pozostaje przy poprzedniej poprawnej polityce w pamięci.

`rule_count` oznacza liczbę wpisów polityk DSL w aktywnym bundle.

### 6.5. `HEARTBEAT`

Event:

```text
timestamp_ms       : varlong
mode               : varint
loaded_revision_id : varlong
policy_hash        : varlong
uptime_sec         : varlong
last_error_code    : varint
```

## 7. Format `RGPF/1`

### 7.1. Założenie

`policy.bin` nie przechowuje skompilowanego drzewa runtime filtrowania.

`policy.bin` jest kontenerem rewizji, który przechowuje:

- nagłówek pliku,
- tablicę sekcji,
- tabelę wpisów polityk,
- tabelę blobów UTF-8 z nazwami i źródłami DSL,
- jeden globalny `default_verdict`,
- opcjonalne dodatkowe sekcje binarne, na przykład sekcję NAT.

Każdy wpis polityki zawiera:

- `name`
- `priority`
- `dsl_source`

Firewall kompiluje każdą politykę DSL do runtime dopiero podczas ładowania rewizji.

### 7.2. Kodowanie liczb

`RGPF/1` nie używa `varint` ani `varlong`.

Wszystkie pola liczbowe są fixed-width i little-endian:

- `u8`
- `u16`
- `u32`
- `u64`

### 7.3. Układ pliku

Plik składa się z:

1. nagłówka,
2. tablicy sekcji,
3. sekcji `POLICY_ENTRY_TABLE`,
4. sekcji `POLICY_SOURCE_TABLE`,
5. sekcji `DEFAULT_VERDICT`,
6. opcjonalnych sekcji dodatkowych, obecnie opcjonalnie `NAT_RULE_TABLE`.

## 8. Nagłówek `RGPF/1`

```c
struct RgpfHeader {
    u32 magic;               // "RGPF"
    u16 major;               // 1
    u16 minor;               // 0
    u16 header_len;
    u16 section_count;
    u32 flags;
    u64 revision_id;
    u64 compiled_at_unix_ms;
    u64 policy_hash;
    u64 section_table_offset;
    u64 file_len;
    u32 file_crc32c;
    u32 reserved;
};
```

Znaczenie kluczowych pól:

- `revision_id`: numer rewizji polityki,
- `policy_hash`: hash logicznej zawartości polityki,
- `file_crc32c`: checksum całego pliku przy wyzerowanym polu `file_crc32c`.

## 9. Tablica sekcji

```c
struct SectionEntry {
    u16 kind;
    u16 flags;
    u64 offset;
    u64 length;
    u32 item_count;
    u32 reserved;
    u64 section_hash;
};
```

Zaimplementowane typy sekcji:

- `1 = POLICY_ENTRY_TABLE`
- `2 = POLICY_SOURCE_TABLE`
- `3 = DEFAULT_VERDICT`
- `4 = NAT_RULE_TABLE` jako sekcja opcjonalna

Pozostałe historyczne typy sekcji mogą nadal istnieć w kodzie pomocniczym repo, ale nie są już częścią aktywnego kontraktu filtrowania.

Jeśli `NAT_RULE_TABLE` jest obecna, musi przejść walidację strukturalną i semantyczną. Błąd tej sekcji blokuje aktywację całej rewizji.

## 10. Sekcja `POLICY_ENTRY_TABLE`

Sekcja przechowuje rekordy stałej długości:

```c
struct PolicyEntry {
    u32 name_off;
    u32 priority;
    u32 source_off;
    u32 reserved;
};
```

Znaczenie pól:

- `name_off` wskazuje nazwę polityki w `POLICY_SOURCE_TABLE`,
- `priority` określa kolejność wykonania,
- `source_off` wskazuje źródło DSL polityki w `POLICY_SOURCE_TABLE`.

Reguły:

- niższa liczba oznacza wyższy priorytet,
- duplikaty `priority` są błędem walidacji,
- tabela nie może być pusta.

## 11. Sekcja `POLICY_SOURCE_TABLE`

Sekcja przechowuje bloby UTF-8 zakodowane jako:

```text
u32 length
bytes[length]
```

W sekcji znajdują się:

- nazwy polityk,
- źródła DSL polityk,
- opcjonalny komunikat globalnego `default_verdict`, jeśli jest typu `AllowWarn` albo `DropWarn`.

Właściwości:

- bez terminatora `NUL`,
- UTF-8,
- odczyt zero-copy z walidacją granic i UTF-8.

## 12. Sekcja `DEFAULT_VERDICT`

Sekcja przechowuje dokładnie jeden rekord:

```c
struct DefaultVerdictEntry {
    u8  verdict_kind;
    u8  reserved0;
    u16 reserved1;
    u32 message_off;
};
```

`verdict_kind`:

- `1 = Allow`
- `2 = Drop`
- `3 = AllowWarn`
- `4 = DropWarn`

Reguły:

- `Allow` i `Drop` muszą mieć `message_off = 0`,
- `AllowWarn` i `DropWarn` muszą mieć poprawny `message_off` do `POLICY_SOURCE_TABLE`.

Jest to jeden globalny `default_verdict` dla całego pliku.

## 13. Ładowanie i aktywacja rewizji

Procedura po stronie firewalla:

1. odczytaj symlink `active`,
2. sprawdź, że wskazuje `versions/<revision>`,
3. odczytaj `active/policy.bin`,
4. sparsuj `RGPF/1`,
5. sprawdź zgodność:
   - rewizji z requestu IPC,
   - rewizji z targetu symlinka,
   - `header.revision_id`,
6. odczytaj `POLICY_ENTRY_TABLE`,
7. odczytaj `POLICY_SOURCE_TABLE`,
8. odczytaj `DEFAULT_VERDICT`,
9. skompiluj każdą politykę DSL do runtime,
10. zbuduj bundle polityk posortowany po `priority`,
11. przy sukcesie aktywuj nową rewizję,
12. przy błędzie pozostaw poprzednią rewizję aktywną.

Semantyka runtime:

- polityki są wykonywane rosnąco po `priority`,
- pierwsza polityka, która zwróci werdykt, kończy ewaluację,
- jeśli żadna polityka nie dopasuje pakietu, używany jest globalny `default_verdict`.

## 14. Rollback i retencja stanu

Rollback jest realizowany w pamięci:

- jeśli nowa rewizja nie przejdzie walidacji lub kompilacji,
- aktywna polityka runtime nie jest podmieniana,
- firewall pozostaje przy ostatniej poprawnej rewizji,
- `FirewallMode` przechodzi w `DEGRADED`,
- `last_error_code` jest aktualizowane.

Firewall nie cofa symlinka `active`. Za publikację rewizji i ewentualne dalsze działania po stronie magazynu odpowiada backend.

## 15. Stan aktualnej implementacji

Aktualnie zaimplementowane są:

- parser `RGPF/1` typu zero-copy dla nagłówka, tablicy sekcji, `POLICY_ENTRY_TABLE`, `POLICY_SOURCE_TABLE` i `DEFAULT_VERDICT`,
- walidacja:
  - `magic`,
  - wersji,
  - `header_len`,
  - `file_len`,
  - `CRC32C`,
  - zakresów sekcji,
  - obecności sekcji `POLICY_ENTRY_TABLE`, `POLICY_SOURCE_TABLE` i `DEFAULT_VERDICT`,
  - poprawności UTF-8 nazw i źródeł DSL,
  - braku duplikatów `priority`,
- loader `RGPF/1 -> CompiledPolicy`, który kompiluje wszystkie polityki DSL w runtime,
- runtime firewalla z bootstrapem z `active/policy.bin`,
- aktywacja rewizji przez `ACTIVATE_REVISION`,
- retain-last-good w pamięci przy błędzie,
- opcjonalne parsowanie i walidację sekcji `NAT_RULE_TABLE`, która przy błędzie blokuje aktywację rewizji, ale nadal nie jest jeszcze ładowana do aktywnego runtime NAT.

## 16. Ograniczenia

Na dziś:

- `CompiledPolicy` jest bundlem wielu polityk DSL, ale każda pojedyncza polityka nadal kompiluje się do obecnego `PolicyEvaluator`,
- sekcja NAT nie jest jeszcze mapowana do aktywnego runtime NAT,
- backend-side publikacji i triggera nie jest opisem implementacji backendu, tylko kontraktem integracyjnym dla firewalla.
