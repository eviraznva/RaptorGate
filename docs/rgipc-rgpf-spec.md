# Specyfikacja `RGIPC/1` i `RGPF/1`

## Status dokumentu

Ten dokument opisuje **aktualnie zaimplementowany** protokół IPC i **aktualnie zaimplementowany** binarny format polityki dla RaptorGate.

Dokument został dopasowany do bieżącego stanu repozytorium. Na dziś w kodzie znajdują się:

- działające `RGIPC/1` nad `AF_UNIX/SOCK_STREAM`,
- typowane wiadomości IPC oparte o `IpcMessage`, `IpcRequestMessage`, `IpcResponseMessage` i `IpcEventMessage`,
- endpoint synchroniczny `SyncIpcEndpoint` i endpoint asynchroniczny `AsyncIpcEndpoint`,
- runtime po stronie firewalla używający lokalnych gniazd synchronicznego i asynchronicznego IPC,
- parser `RGPF/1` typu zero-copy oparty o `zerocopy`,
- loader `RGPF/1 -> CompiledPolicy`, który obecnie obsługuje dokładnie jedno drzewo reguł filtrowania,
- parser i walidator sekcji `NAT_RULE_TABLE`, ale bez pełnego załadowania NAT do aktywnego runtime.

Dokument należy traktować jako opis obowiązującego kontraktu oraz jego bieżących ograniczeń implementacyjnych.

## 1. Cel

Kontrakt systemowy rozdziela odpowiedzialności w prosty sposób:

- backend waliduje konfigurację źródłową i publikuje rewizję,
- firewall ładuje lokalną migawkę `active/policy.bin`,
- IPC służy wyłącznie do komunikacji sterującej i zgłaszania stanu procesu,
- `policy.bin` jest skompilowaną reprezentacją polityki wykonywanej w firewallu, a nie kopią backendowego modelu danych.

## 2. Zakres

Specyfikacja definiuje:

- `RGIPC/1`: lokalny protokół IPC nad `AF_UNIX/SOCK_STREAM`,
- `RGPF/1`: binarny format pliku `policy.bin`,
- semantykę ładowania, walidacji i aktywacji rewizji polityki.

Poza zakresem dokumentu pozostają:

- transport inny niż UDS,
- serializacja pełnego backendowego modelu konfiguracji,
- aktywny runtime NAT po stronie loadera `RGPF/1`,
- QoS, DPI, identity, VLAN, app-id i inne funkcje spoza obecnego evaluatora polityki.

## 3. Architektura IPC

### 3.1. Gniazda

Komunikacja lokalna używa dwóch gniazd Unix Domain Socket:

- `rg-synchronous.sock`
- `rg-asynchronous.sock`

### 3.2. Role kanałów

`rg-synchronous.sock` służy do komunikacji typu żądanie-odpowiedź:

- `PING`
- `GET_STATUS`
- `GET_NETWORK_INTERFACES`

`rg-asynchronous.sock` służy do komunikacji zdarzeniowej:

- `HEARTBEAT`

### 3.3. Transport

Warstwa transportowa:

- `AF_UNIX`
- `SOCK_STREAM`
- własne ramkowanie na poziomie aplikacji

Kolejność wiadomości wynika z kolejności bajtów w strumieniu. Granicę wiadomości wyznacza pole `payload_len`.

## 4. Model wiadomości `RGIPC/1`

Protokół wspiera dwa modele wymiany:

- żądanie-odpowiedź: `REQUEST -> RESPONSE | ERROR`
- komunikacja zdarzeniowa: `EVENT` bez wymaganej odpowiedzi

W aktualnej implementacji jedynym zdefiniowanym zdarzeniem jest `HEARTBEAT`.

### 4.1. Typy pól

W `RGIPC/1` wszystkie liczby całkowite są kodowane jako:

- `varint` dla wartości do 32 bitów,
- `varlong` dla wartości do 64 bitów.

Normatywnie:

- `varint` = unsigned LEB128 dla `u32`,
- `varlong` = unsigned LEB128 dla `u64`.

Łańcuch znaków ma postać:

- `len : varint`
- `bytes[len]`, UTF-8, bez terminatora `NUL`

`bool` jest kodowany jako `varint`:

- `0 = false`
- `1 = true`

### 4.2. Format ramki

`RGIPC/1` nie definiuje stałej struktury nagłówka. Ramka jest zapisywana pole po polu:

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

Kolejność i typy:

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

### 4.3. Znaczenie pól

`magic`

- stały identyfikator protokołu,
- wartość logiczna: `RGIPC_MAGIC`,
- rekomendowana wartość liczbowa: `0x52474950` (`"RGIP"`),
- na połączeniu nadal kodowana jako `varint`.

`version`

- wersja protokołu,
- dla tej specyfikacji: `1`.

`kind`

- `1 = EVENT`
- `2 = REQUEST`
- `3 = RESPONSE`
- `4 = ERROR`

`flags`

- `0x00 = NONE`
- `0x01 = ACK_REQUIRED`
- `0x02 = CRITICAL`
- `0x04 = NO_REPLY`

`opcode`

- kod operacji albo zdarzenia.

`status`

- dla `REQUEST` i `EVENT` powinno być `0`,
- dla `RESPONSE` i `ERROR` niesie kod wyniku.

`request_id`

- identyfikator korelacyjny,
- dla `REQUEST` musi być niezerowy,
- dla `RESPONSE` i `ERROR` musi powtarzać `request_id` żądania,
- dla `EVENT` może mieć wartość `0`.

`sequence_no`

- rosnący numer wiadomości w obrębie jednego połączenia,
- służy diagnostyce i korelacji logów,
- nie służy do retransmisji ani odtwarzania kolejności.

`payload_len`

- liczba bajtów w polu `payload`.

### 4.4. Zasady kodowania danych

Każdy ładunek IPC używa tych samych reguł:

- liczby całkowite: `varint` albo `varlong`,
- łańcuch znaków: `len + bytes`,
- lista: `count : varint`, a następnie elementy,
- brak paddingu i wyrównania,
- brak opcjonalnych pól ukrywanych przez skracanie końca wiadomości.

W `RGIPC/1` pole albo występuje zawsze, albo wymaga nowej wersji ładunku lub nowej wersji protokołu.

## 5. Rejestr `opcode`

### 5.1. Operacje żądanie-odpowiedź

- `0x01 = PING`
- `0x02 = GET_STATUS`
- `0x03 = GET_NETWORK_INTERFACES`

### 5.2. Zdarzenia

- `0x100 = HEARTBEAT`

## 6. Wiadomości `RGIPC/1`

### 6.1. `PING`

Kanał:

- `rg-synchronous.sock`

Typ:

- żądanie: `REQUEST`
- odpowiedź: `RESPONSE`

Cel:

- sprawdzenie dostępności drugiej strony,
- pomiar czasu rundy.

Ładunek żądania:

```text
timestamp_ms : varlong
```

Ładunek odpowiedzi:

```text
timestamp_ms      : varlong
peer_timestamp_ms : varlong
```

### 6.2. `GET_STATUS`

Kanał:

- `rg-synchronous.sock`

Typ:

- żądanie: `REQUEST`
- odpowiedź: `RESPONSE`

Ładunek żądania:

- pusty

Ładunek odpowiedzi:

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

Kanał:

- `rg-synchronous.sock`

Typ:

- żądanie: `REQUEST`
- odpowiedź: `RESPONSE`

Ładunek żądania:

- pusty

Ładunek odpowiedzi:

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

Uwagi wdrożeniowe dla MVP:

- wszystkie pola z powyższego układu pozostają obowiązkowe,
- jeśli runtime nie zna `mtu`, `mac` albo listy adresów, zwraca wartości zerowe,
- `mac_len = 0` i `ip_count = 0` są prawidłowe.

### 6.4. `HEARTBEAT`

Kanał:

- `rg-asynchronous.sock`

Typ:

- `EVENT`

Ładunek:

```text
timestamp_ms       : varlong
mode               : varint
loaded_revision_id : varlong
policy_hash        : varlong
uptime_sec         : varlong
last_error_code    : varint
```

Rekomendowany interwał:

- `5 s`, albo
- `10 s`

## 7. Kody statusu

### 7.1. Statusy ogólne

- `0 = OK`
- `1 = ACCEPTED`

### 7.2. Błędy protokołu

- `100 = ERR_BAD_MAGIC`
- `101 = ERR_UNSUPPORTED_VERSION`
- `102 = ERR_BAD_FRAME`
- `103 = ERR_BAD_PAYLOAD_LEN`
- `104 = ERR_UNSUPPORTED_OPCODE`
- `105 = ERR_MALFORMED_PAYLOAD`

### 7.3. Błędy wykonania

- `200 = ERR_INTERNAL`
- `201 = ERR_POLICY_NOT_LOADED`
- `202 = ERR_INTERFACE_ENUM_FAILED`

## 8. Cykl życia połączeń IPC

### 8.1. Kanał synchroniczny

Kanał synchroniczny w aktualnej implementacji jest modelowany jako **dwukierunkowy endpoint** request-response. Oznacza to, że każda strona połączenia może:

1. otwiera połączenie,
2. wysyłać `REQUEST`,
3. odbierać `REQUEST`,
4. odsyłać `RESPONSE` albo `ERROR`,
5. utrzymywać połączenie dla kolejnych wiadomości albo je zamknąć.

W repo odpowiada za to typ `SyncIpcEndpoint`, który:

- buduje `REQUEST` z typowanego requestu,
- waliduje `magic`, `version`, `kind`, `opcode`, `request_id` i `status`,
- potrafi odbierać typowane requesty od drugiej strony,
- potrafi odsyłać typowane `RESPONSE` i surowe `ERROR`.

W `RGIPC/1` nie ma osobnego komunikatu `HELLO`.

### 8.2. Kanał asynchroniczny

Kanał asynchroniczny w aktualnej implementacji jest modelowany jako endpoint zdarzeń. Po stronie repo odpowiada za to `AsyncIpcEndpoint`, który:

- wysyła typowane `EVENT`,
- automatycznie ustawia `kind = EVENT`, `request_id = 0` i kolejny `sequence_no`,
- potrafi odbierać typowane eventy i walidować `magic`, `version`, `opcode`, `request_id` i `status`.

W aktualnym runtime firewalla:

1. otwiera połączenie,
2. utrzymuje je przez cały czas działania sesji,
3. wysyła okresowo `HEARTBEAT`.

## 9. Założenia `RGPF/1`

### 9.1. Cel formatu

`policy.bin` jest:

- lokalną migawką stanu polityki,
- skompilowaną reprezentacją polityki,
- formatem zoptymalizowanym pod szybkie ładowanie i prostą walidację.

### 9.2. Podstawowe reguły serializacji

`RGPF/1` nie używa `varint` ani `varlong`.

Wszystkie pola liczbowe mają stałą szerokość:

- `u8`
- `u16`
- `u32`
- `u64`

Wszystkie wartości wielobajtowe są zapisane jako:

- little-endian

Struktury pokazane w dokumencie opisują układ bajtów w pliku, a nie układ pamięci kompilatora. Serializacja odbywa się pole po polu, bez ukrytego paddingu.

Wszystkie offsety zapisane wewnątrz sekcji są liczone od początku danej sekcji, chyba że przy polu zapisano inaczej.

### 9.2.1. Stan implementacji parsera

Aktualna implementacja repozytorium używa parsera typu zero-copy.

Oznacza to, że:

- plik `policy.bin` jest parsowany na widoki oparte o `&[u8]`,
- rekordy stałej szerokości są mapowane bezpośrednio z bufora wejściowego,
- rekordy zmiennej długości i wszystkie offsety są sprawdzane jawnie pod kątem granic bufora,
- parser korzysta z biblioteki `zerocopy` do bezpiecznego mapowania struktur fixed-size,
- alokacje są dopuszczalne dopiero na etapie loadera do aktualnego runtime.

### 9.3. Zakres `v1`

Format `policy.bin v1` obejmuje tylko to, co zna obecny evaluator polityki.

`MatchKind`:

- `SrcIp`
- `DstIp`
- `IpVer`
- `DayOfWeek`
- `Hour`
- `Protocol`
- `SrcPort`
- `DstPort`

`Pattern`:

- `Wildcard`
- `Equal`
- `Glob`
- `Range`
- `Comparison`
- `Or`

`Verdict`:

- `Allow`
- `Drop`
- `AllowWarn(String)`
- `DropWarn(String)`

Dodatkowo format przewiduje przechowywanie reguł NAT w postaci logicznie odpowiadającej:

```rust
pub struct NatRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: u32,
    pub applies_at: NatStage,
    pub match_criteria: RuleMatch,
    pub kind: NatKind,
    pub timeouts: NatTimeouts,
}
```

W obecnym kodzie repozytorium pełna wersja tego modelu nie jest jeszcze zaimplementowana. Istnieje jedynie uproszczona reprezentacja runtime `NatRuleDummy`, która zawiera podzbiór pól potrzebnych do obecnego silnika NAT.

Aktualny parser `RGPF/1` potrafi już:

- parsować sekcję `NAT_RULE_TABLE`,
- walidować jej nagłówek, rekordy i referencje,
- udostępniać widoki zero-copy na dane NAT.

Aktualny loader runtime **nie** materializuje jeszcze tej sekcji do aktywnego runtime NAT.

Poza zakresem `v1`:

- strefy,
- VLAN,
- DPI,
- app-id,
- identity,
- QoS,
- rate limits,
- skutki uboczne po stronie runtime.

## 10. Układ pliku `policy.bin`

Plik składa się z:

1. nagłówka,
2. tablicy sekcji,
3. sekcji `STRING_TABLE`,
4. sekcji `RULE_TREE_TABLE`,
5. sekcji `DEFAULT_VERDICT`,
6. opcjonalnej sekcji `NAT_RULE_TABLE`.

Osobna sekcja metadanych nie jest wymagana w `v1`, ponieważ metadane rewizji znajdują się już w nagłówku.

## 11. Nagłówek `RGPF/1`

```c
struct RgpfHeader {
    u32 magic;               // "RGPF"
    u16 major;               // 1
    u16 minor;               // 0
    u16 header_len;          // 64
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

Znaczenie pól:

- `magic`: identyfikator formatu, ASCII `"RGPF"`,
- `major`, `minor`: wersja formatu,
- `header_len`: długość nagłówka w bajtach,
- `section_count`: liczba wpisów w tablicy sekcji,
- `flags`: pole zarezerwowane, w `v1 = 0`,
- `revision_id`: numer rewizji polityki,
- `compiled_at_unix_ms`: czas kompilacji,
- `policy_hash`: skrót logicznej zawartości polityki,
- `section_table_offset`: offset tablicy sekcji od początku pliku,
- `file_len`: długość całego pliku,
- `file_crc32c`: CRC32C całego pliku przy wyzerowanym polu `file_crc32c`,
- `reserved`: `0`.

## 12. Tablica sekcji

```c
struct SectionEntry {
    u16 kind;
    u16 flags;
    u64 offset;        // od początku pliku
    u64 length;
    u32 item_count;
    u32 reserved;
    u64 section_hash;
};
```

Typy sekcji:

- `1 = STRING_TABLE`
- `2 = RULE_TREE_TABLE`
- `3 = DEFAULT_VERDICT`
- `4 = NAT_RULE_TABLE`

Uwagi:

- `offset` jest liczony od początku pliku,
- `length` jest długością danych sekcji w bajtach,
- `item_count` oznacza liczbę logicznych elementów danej sekcji,
- `section_hash` w `v1` może mieć wartość `0`, jeśli implementacja nie utrzymuje osobnych skrótów sekcji.

## 13. Sekcja `STRING_TABLE`

Sekcja przechowuje:

- nazwy reguł,
- opisy reguł,
- komunikaty dla verdictów `AllowWarn` i `DropWarn`.

Każdy wpis:

```c
struct StringEntry {
    u32 length;
    u8  bytes[length];
};
```

Zasady:

- łańcuchy są zapisane jako UTF-8,
- nie są zakończone `NUL`,
- offset wskazuje na początek `StringEntry`, a nie na samo `bytes`.

## 14. Sekcja `RULE_TREE_TABLE`

### 14.1. Cel

Sekcja zapisuje skompilowaną reprezentację semantyki polityki wykonywanej w firewallu. Nie jest to zrzut AST ani kopia struktur Rust w pamięci.

W szczególności:

- `Match` z wieloma ramionami jest obniżany do liniowego grafu węzłów,
- kolejność ramion jest zachowana przez łańcuch `no_index`,
- wygrywa pierwsze pasujące ramię.

### 14.2. Nagłówek sekcji

```c
struct RuleTreeSectionHeader {
    u32 rule_count;
    u32 node_count;
    u32 verdict_count;
    u32 reserved0;
    u64 rules_offset;
    u64 nodes_offset;
    u64 object_arena_offset;
    u64 object_arena_len;
};
```

Sekcja zawiera:

- tablicę `RuleEntry[rule_count]`,
- tablicę `RuleNode[node_count]`,
- wspólny obszar danych dla `PatternEntry`, `FieldValue` i `VerdictEntry`.

Wszystkie offsety wewnątrz tej sekcji są liczone od początku sekcji.

### 14.3. Wpis reguły

```c
struct RuleEntry {
    u32 rule_id;
    u32 name_str_off;      // offset do StringEntry w STRING_TABLE
    u32 desc_str_off;      // offset do StringEntry w STRING_TABLE
    u32 root_node_index;
};
```

Kolejność `RuleEntry` w tablicy jest kolejnością ewaluacji reguł.

### 14.4. Reprezentacja węzła

```c
struct RuleNode {
    u8  node_kind;         // 1=MATCH, 2=VERDICT
    u8  match_kind;        // tylko dla MATCH
    u16 reserved0;
    u32 pattern_off;       // offset do PatternEntry, albo 0
    u32 yes_index;         // indeks kolejnego węzła albo 0xFFFFFFFF
    u32 no_index;          // indeks kolejnego węzła albo 0xFFFFFFFF
    u32 verdict_off;       // offset do VerdictEntry, albo 0
};
```

`node_kind`:

- `1 = MATCH`
- `2 = VERDICT`

`match_kind`:

- `1 = SrcIp`
- `2 = DstIp`
- `3 = IpVer`
- `4 = DayOfWeek`
- `5 = Hour`
- `6 = Protocol`
- `7 = SrcPort`
- `8 = DstPort`

Semantyka:

- dla `MATCH`, `pattern_off` musi być niezerowy, a `verdict_off = 0`,
- dla `VERDICT`, `verdict_off` musi być niezerowy, a `pattern_off = 0`,
- `yes_index` wskazuje ścieżkę po dopasowaniu,
- `no_index` wskazuje kolejne ramię albo kolejny test przy braku dopasowania,
- `0xFFFFFFFF` oznacza koniec ścieżki.

## 15. `PatternEntry`

Każdy wzorzec w obszarze danych zaczyna się wspólnym nagłówkiem:

```c
struct PatternEntryHeader {
    u8  pattern_kind;
    u8  reserved0;
    u16 reserved1;
};
```

`pattern_kind`:

- `1 = Wildcard`
- `2 = Equal`
- `3 = Glob`
- `4 = Range`
- `5 = Comparison`
- `6 = Or`

### 15.1. `Wildcard`

Brak dodatkowego ładunku poza `PatternEntryHeader`.

### 15.2. `Equal`

```c
struct EqualPattern {
    PatternEntryHeader header;  // kind = 2
    u32 field_value_off;
};
```

### 15.3. `Glob`

W `RGPF/1` `Glob` wspiera tylko `Ip`.

```c
struct GlobPattern {
    PatternEntryHeader header;  // kind = 3
    u32 field_value_off;
};
```

### 15.4. `Range`

```c
struct RangePattern {
    PatternEntryHeader header;  // kind = 4
    u32 lo_value_off;
    u32 hi_value_off;
};
```

Obsługiwane zakresy:

- `Port..Port`
- `Hour..Hour`

### 15.5. `Comparison`

```c
struct ComparisonPattern {
    PatternEntryHeader header;  // kind = 5
    u8  op;
    u8  reserved0;
    u16 reserved1;
    u32 rhs_value_off;
};
```

`op`:

- `1 = Greater`
- `2 = Lesser`
- `3 = GreaterOrEqual`
- `4 = LesserOrEqual`

Obsługiwane typy:

- `Port`
- `Hour`
- `DayOfWeek`

### 15.6. `Or`

```c
struct OrPattern {
    PatternEntryHeader header;  // kind = 6
    u32 pattern_count;
    u32 pattern_offsets[pattern_count];
};
```

Każdy wpis w `pattern_offsets` wskazuje na inny `PatternEntry`.

W `v1` `Or` może być użyte tylko dla:

- `Protocol`
- `DayOfWeek`
- `IpVer`
- `Hour`
- `SrcIp`
- `DstIp`

To odpowiada aktualnej walidacji runtime.

## 16. `FieldValue`

Każda wartość używana we wzorcach jest typowana.

### 16.1. Nagłówek wartości

```c
struct FieldValueHeader {
    u8  type_tag;
    u8  reserved0;
    u16 reserved1;
};
```

`type_tag`:

- `1 = Ip`
- `2 = IpVer`
- `3 = DayOfWeek`
- `4 = Hour`
- `5 = Protocol`
- `6 = Port`

### 16.2. `Ip`

Model odpowiada aktualnemu runtime `IP` z wildcard-octets.

```c
struct IpValue {
    FieldValueHeader header;    // type_tag = 1
    u8 octet0;
    u8 octet1;
    u8 octet2;
    u8 octet3;
    u8 mask0;                   // 0=value, 1=any
    u8 mask1;
    u8 mask2;
    u8 mask3;
};
```

### 16.3. `Port`

```c
struct PortValue {
    FieldValueHeader header;    // type_tag = 6
    u16 value;
};
```

### 16.4. `Hour`

```c
struct HourValue {
    FieldValueHeader header;    // type_tag = 4
    u8 value;
    u8 reserved[3];
};
```

### 16.5. `Protocol`

```c
struct ProtocolValue {
    FieldValueHeader header;    // type_tag = 5
    u8 value;
    u8 reserved[3];
};
```

### 16.6. `DayOfWeek`

```c
struct DayOfWeekValue {
    FieldValueHeader header;    // type_tag = 3
    u8 value;
    u8 reserved[3];
};
```

### 16.7. `IpVer`

```c
struct IpVerValue {
    FieldValueHeader header;    // type_tag = 2
    u8 value;
    u8 reserved[3];
};
```

## 17. `VerdictEntry`

```c
struct VerdictEntry {
    u8  verdict_kind;       // 1=Allow, 2=Drop, 3=AllowWarn, 4=DropWarn
    u8  reserved0;
    u16 reserved1;
    u32 message_str_off;    // offset do StringEntry w STRING_TABLE, 0 jeśli brak
};
```

`verdict_kind`:

- `1 = Allow`
- `2 = Drop`
- `3 = AllowWarn`
- `4 = DropWarn`

## 18. Sekcja `DEFAULT_VERDICT`

Sekcja zawiera dokładnie jeden:

```c
struct VerdictEntry
```

Jest to domyślny werdykt używany wtedy, gdy żadna reguła nie zakończy ewaluacji werdyktem.

## 18.1. Sekcja `NAT_RULE_TABLE`

Format `RGPF/1` przewiduje możliwość przechowywania również reguł NAT. Sekcja ta jest opcjonalna na poziomie pliku, ale jest już obsługiwana przez aktualny parser i walidator repozytorium.

Celem tej sekcji jest zapis reguł NAT w formie skompilowanej, ale nadal bliskiej modelowi domenowemu:

```rust
pub struct NatRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: u32,
    pub applies_at: NatStage,
    pub match_criteria: RuleMatch,
    pub kind: NatKind,
    pub timeouts: NatTimeouts,
}
```

Stan obecny repozytorium:

- pełny model `NatRule` nie jest jeszcze zaimplementowany po stronie runtime,
- aktualny silnik NAT używa uproszczonej struktury `NatRuleDummy`,
- uproszczona wersja zawiera obecnie pola: `id`, `priority`, `match_criteria`, `kind`, `timeouts`,
- `NatStage` istnieje już w kodzie i wspiera wartości `Prerouting` oraz `Postrouting`.

Stan implementacji `RGPF/1`:

- sekcja `NAT_RULE_TABLE` jest parsowana,
- sekcja `NAT_RULE_TABLE` jest walidowana,
- brak jeszcze adaptera, który ładuje te dane do aktywnego runtime NAT.

Wymagania dla formatu binarnego:

- `id` i `name` powinny być przechowywane jako offsety do `STRING_TABLE`,
- `enabled` powinno być zapisane jako `u8`,
- `priority` jako `u32`,
- `applies_at` jako mały enum o stałej szerokości,
- `match_criteria`, `kind` i `timeouts` powinny być zapisane jako osobne rekordy lub rekordy zagnieżdżone w obrębie sekcji NAT,
- kolejność wpisów NAT powinna zachowywać priorytet ewaluacji po stronie runtime.

Minimalna zgodność z aktualnym runtime:

- pierwsza wersja serializacji NAT może odwzorowywać tylko obecny zakres `NatRuleDummy`,
- pola `name`, `enabled` i `applies_at` mogą być obecne w pliku nawet wtedy, gdy runtime ich jeszcze nie wykorzystuje,
- rozwinięcie do pełnego `NatRule` nie wymaga zmiany ogólnej architektury `RGPF/1`, a jedynie doprecyzowania układu sekcji `NAT_RULE_TABLE`.

### 18.1.1. Nagłówek sekcji NAT

Sekcja `NAT_RULE_TABLE` powinna mieć własny nagłówek:

```c
struct NatRuleSectionHeader {
    u32 rule_count;
    u32 match_count;
    u32 kind_count;
    u32 timeout_count;
    u64 rules_offset;
    u64 matches_offset;
    u64 kinds_offset;
    u64 timeouts_offset;
    u64 object_arena_offset;
    u64 object_arena_len;
};
```

Sekcja zawiera:

- tablicę `NatRuleEntry[rule_count]`,
- tablicę `NatMatchEntry[match_count]`,
- tablicę `NatKindEntry[kind_count]`,
- tablicę `NatTimeoutsEntry[timeout_count]`,
- wspólny obszar danych dla rekordów pomocniczych.

Wszystkie offsety wewnątrz sekcji są liczone od początku sekcji.

### 18.1.2. Wpis reguły NAT

Każda reguła NAT jest zapisana jako:

```c
struct NatRuleEntry {
    u32 id_str_off;         // offset do StringEntry w STRING_TABLE
    u32 name_str_off;       // offset do StringEntry w STRING_TABLE
    u8  enabled;
    u8  applies_at;         // NatStage
    u16 reserved0;
    u32 priority;
    u32 match_index;        // indeks do NatMatchEntry
    u32 kind_index;         // indeks do NatKindEntry
    u32 timeouts_index;     // indeks do NatTimeoutsEntry
};
```

Zasady:

- `id_str_off` musi być niezerowy,
- `name_str_off` może być `0`, jeśli nazwa nie jest ustawiona,
- `enabled`: `0 = false`, `1 = true`,
- `priority` określa kolejność ewaluacji reguł,
- kolejność wpisów w tablicy powinna odpowiadać kolejności używanej przez runtime po posortowaniu.

### 18.1.3. `NatStage`

`applies_at` jest małym enumem:

- `1 = Prerouting`
- `2 = Postrouting`

To odpowiada aktualnemu modelowi runtime.

### 18.1.4. Kryteria dopasowania `RuleMatch`

Kryteria dopasowania są zapisywane jako osobny rekord:

```c
struct NatMatchEntry {
    u32 presence_bits;
    u32 in_interface_str_off;
    u32 out_interface_str_off;
    u32 in_zone_str_off;
    u32 out_zone_str_off;
    u32 src_cidr_off;
    u32 dst_cidr_off;
    u32 proto_off;
    u32 src_ports_off;
    u32 dst_ports_off;
};
```

`presence_bits`:

- `0x001 = in_interface`
- `0x002 = out_interface`
- `0x004 = in_zone`
- `0x008 = out_zone`
- `0x010 = src_cidr`
- `0x020 = dst_cidr`
- `0x040 = proto`
- `0x080 = src_ports`
- `0x100 = dst_ports`

Zasady:

- jeśli bit obecności nie jest ustawiony, odpowiadające pole offsetowe musi mieć wartość `0`,
- jeśli bit obecności jest ustawiony, odpowiadające pole offsetowe musi być niezerowe,
- taki zapis odpowiada aktualnej semantyce `Option<T>` używanej w `RuleMatchDummy`.

### 18.1.5. Rekord `CidrEntry`

Dla `src_cidr` i `dst_cidr` używany jest wspólny rekord:

```c
struct CidrEntry {
    u8  ip_version;         // 4 albo 6
    u8  prefix_len;
    u16 reserved0;
    u8  addr[16];
};
```

Zasady:

- dla IPv4 używane są pierwsze 4 bajty `addr`, pozostałe muszą być wyzerowane,
- dla IPv6 używane jest całe `addr[16]`,
- `prefix_len` musi być zgodny z wersją adresu.

### 18.1.6. Rekord `NatProtoEntry`

Protokół warstwy 4 jest zapisywany jako:

```c
struct NatProtoEntry {
    u8  proto_kind;
    u8  reserved0;
    u16 reserved1;
};
```

`proto_kind`:

- `1 = Any`
- `2 = Tcp`
- `3 = Udp`
- `4 = Icmp`

To odpowiada aktualnemu `NatProtoDummy`.

### 18.1.7. Rekord `PortRangeEntry`

Zakres portów:

```c
struct PortRangeEntry {
    u16 start;
    u16 end;
};
```

Zasady:

- `start <= end`,
- zakres jest domknięty po obu stronach,
- odpowiada to aktualnej semantyce `PortRangeDummy`.

### 18.1.8. Rodzaj translacji `NatKind`

Każdy rodzaj NAT jest zapisywany przez wspólny nagłówek i payload zależny od wariantu:

```c
struct NatKindEntryHeader {
    u8  kind_tag;
    u8  reserved0;
    u16 reserved1;
};
```

`kind_tag`:

- `1 = Snat`
- `2 = Masquerade`
- `3 = Dnat`
- `4 = Pat`

#### `Snat`

```c
struct SnatKindEntry {
    NatKindEntryHeader header;  // kind_tag = 1
    u32 to_addr_off;            // offset do CidrAddressEntry
};
```

#### `Masquerade`

```c
struct MasqueradeKindEntry {
    NatKindEntryHeader header;  // kind_tag = 2
    u32 interface_str_off;      // offset do StringEntry
    u32 port_pool_off;          // offset do PortRangeEntry albo 0
};
```

#### `Dnat`

```c
struct DnatKindEntry {
    NatKindEntryHeader header;  // kind_tag = 3
    u32 to_addr_off;            // offset do CidrAddressEntry
    u16 to_port;                // 0 jeśli brak
    u16 reserved0;
};
```

#### `Pat`

```c
struct PatKindEntry {
    NatKindEntryHeader header;  // kind_tag = 4
    u32 to_addr_off;            // offset do CidrAddressEntry albo 0
    u32 interface_str_off;      // offset do StringEntry albo 0
    u32 port_pool_off;          // offset do PortRangeEntry
};
```

### 18.1.9. Rekord `CidrAddressEntry`

Ponieważ warianty `Snat`, `Dnat` i `Pat` operują na pojedynczym adresie IP, używany jest osobny rekord adresowy:

```c
struct CidrAddressEntry {
    u8  ip_version;         // 4 albo 6
    u8  reserved0;
    u16 reserved1;
    u8  addr[16];
};
```

Zasady:

- dla IPv4 wykorzystywane są pierwsze 4 bajty,
- dla IPv6 wykorzystywane jest całe pole `addr`,
- rekord opisuje pojedynczy adres, bez prefiksu sieci.

### 18.1.10. Rekord `NatTimeouts`

Czasy życia translacji są zapisywane jako:

```c
struct NatTimeoutsEntry {
    u8  presence_bits;
    u8  reserved0;
    u16 reserved1;
    u64 tcp_established_s;
    u64 udp_s;
    u64 icmp_s;
};
```

`presence_bits`:

- `0x01 = tcp_established_s`
- `0x02 = udp_s`
- `0x04 = icmp_s`

Zasady:

- jeśli bit obecności nie jest ustawiony, odpowiadające pole czasowe musi mieć wartość `0`,
- jeśli bit obecności jest ustawiony, pole zawiera liczbę sekund,
- taki zapis odwzorowuje obecne `Option<u64>` z `NatTimeoutsDummy`.

### 18.1.11. Semantyka sekcji NAT

Reguły NAT są przetwarzane w kolejności priorytetu, a przy remisie w kolejności występowania w sekcji.

Minimalny zakres funkcjonalny zgodny z aktualnym kodem obejmuje:

- `NatStage`: `Prerouting`, `Postrouting`,
- `NatProto`: `Any`, `Tcp`, `Udp`, `Icmp`,
- `NatKind`: `Snat`, `Masquerade`, `Dnat`, `Pat`,
- `RuleMatch`: interfejsy, strefy, CIDR źródłowy i docelowy, protokół, zakresy portów źródłowych i docelowych,
- `NatTimeouts`: `tcp_established_s`, `udp_s`, `icmp_s`.

## 18.2. Rejestr wartości enum i tagów

Ta sekcja zamyka format przez przypisanie dokładnych wartości liczbowych wszystkim enumom, tagom i kodom używanym w `RGIPC/1` oraz `RGPF/1`.

Zasada ogólna:

- wartości `0` są zarezerwowane jako `INVALID`, `UNSPECIFIED` albo `NONE`, jeśli nie zapisano inaczej,
- każda nowa wartość wymaga aktualizacji specyfikacji,
- zmiana znaczenia istniejącej wartości wymaga nowej wersji formatu.

### 18.2.1. `RGIPC/1`

#### Typ wiadomości `kind`

- `1 = EVENT`
- `2 = REQUEST`
- `3 = RESPONSE`
- `4 = ERROR`

#### Flagi `flags`

- `0x00 = NONE`
- `0x01 = ACK_REQUIRED`
- `0x02 = CRITICAL`
- `0x04 = NO_REPLY`

Flagi mogą być łączone bitowo.

#### `opcode`

- `0x01 = PING`
- `0x02 = GET_STATUS`
- `0x03 = GET_NETWORK_INTERFACES`
- `0x100 = HEARTBEAT`

#### Tryb pracy `mode`

- `1 = NORMAL`
- `2 = DEGRADED`
- `3 = EMERGENCY`

#### Kody statusu

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

### 18.2.2. `RGPF/1` sekcje pliku

#### Typ sekcji `SectionEntry.kind`

- `1 = STRING_TABLE`
- `2 = RULE_TREE_TABLE`
- `3 = DEFAULT_VERDICT`
- `4 = NAT_RULE_TABLE`

#### Wartość logiczna

Jeżeli pole logiczne jest zapisane jako `u8`, obowiązuje:

- `0 = false`
- `1 = true`

Każda inna wartość jest błędem walidacji.

### 18.2.3. Reguły polityki

#### Typ węzła `RuleNode.node_kind`

- `1 = MATCH`
- `2 = VERDICT`

#### Rodzaj dopasowania `RuleNode.match_kind`

- `1 = SrcIp`
- `2 = DstIp`
- `3 = IpVer`
- `4 = DayOfWeek`
- `5 = Hour`
- `6 = Protocol`
- `7 = SrcPort`
- `8 = DstPort`

#### Rodzaj wzorca `PatternEntryHeader.pattern_kind`

- `1 = Wildcard`
- `2 = Equal`
- `3 = Glob`
- `4 = Range`
- `5 = Comparison`
- `6 = Or`

#### Operacja porównania `ComparisonPattern.op`

- `1 = Greater`
- `2 = Lesser`
- `3 = GreaterOrEqual`
- `4 = LesserOrEqual`

#### Typ wartości `FieldValueHeader.type_tag`

- `1 = Ip`
- `2 = IpVer`
- `3 = DayOfWeek`
- `4 = Hour`
- `5 = Protocol`
- `6 = Port`

#### Werdykt `VerdictEntry.verdict_kind`

- `1 = Allow`
- `2 = Drop`
- `3 = AllowWarn`
- `4 = DropWarn`

### 18.2.4. Dokładne wartości typów domenowych polityki

#### `IpVerValue.value`

- `1 = V4`
- `2 = V6`

#### `ProtocolValue.value`

- `1 = Tcp`
- `2 = Udp`
- `3 = Icmp`

#### `DayOfWeekValue.value`

- `1 = Mon`
- `2 = Tue`
- `3 = Wed`
- `4 = Thu`
- `5 = Fri`
- `6 = Sat`
- `7 = Sun`

#### `HourValue.value`

- zakres dopuszczalny: `0..23`

#### `PortValue.value`

- zakres dopuszczalny: `0..65535`

Uwaga walidacyjna:

- jeśli `Pattern` lub `FieldValue` używa wartości spoza powyższych zakresów lub mapowań, plik jest niepoprawny.

### 18.2.5. NAT

#### Etap NAT `NatRuleEntry.applies_at`

- `1 = Prerouting`
- `2 = Postrouting`

#### Protokół NAT `NatProtoEntry.proto_kind`

- `1 = Any`
- `2 = Tcp`
- `3 = Udp`
- `4 = Icmp`

#### Rodzaj translacji `NatKindEntryHeader.kind_tag`

- `1 = Snat`
- `2 = Masquerade`
- `3 = Dnat`
- `4 = Pat`

#### Wersja adresu IP

W rekordach `CidrEntry` i `CidrAddressEntry`:

- `4 = IPv4`
- `6 = IPv6`

#### Bity obecności `NatMatchEntry.presence_bits`

- `0x001 = in_interface`
- `0x002 = out_interface`
- `0x004 = in_zone`
- `0x008 = out_zone`
- `0x010 = src_cidr`
- `0x020 = dst_cidr`
- `0x040 = proto`
- `0x080 = src_ports`
- `0x100 = dst_ports`

#### Bity obecności `NatTimeoutsEntry.presence_bits`

- `0x01 = tcp_established_s`
- `0x02 = udp_s`
- `0x04 = icmp_s`

### 18.2.6. Wartości zarezerwowane i błędne

Poniższe zasady obowiązują w całym formacie:

- `0` w polach enum jest wartością nieprawidłową, chyba że pole jawnie dopuszcza `0`,
- nieznana wartość enum oznacza błąd walidacji,
- nieznany bit poza zdefiniowaną maską oznacza błąd walidacji,
- `0xFFFFFFFF` może być używane wyłącznie jako znacznik końca indeksu w `yes_index` i `no_index`,
- offset `0` jest dopuszczalny tylko tam, gdzie specyfikacja opisuje go jako brak wartości.

## 19. Semantyka ewaluacji

### 19.1. Kolejność reguł

Reguły są ewaluowane w kolejności występowania `RuleEntry` w sekcji `RULE_TREE_TABLE`.

### 19.2. Wynik ewaluacji

- jeśli reguła zakończy się `Verdict`, evaluator zwraca ten werdykt,
- jeśli reguła nie dopasuje się, evaluator przechodzi do kolejnej reguły,
- jeśli żadna reguła nie dopasuje się, zwracany jest `default_verdict`.

### 19.3. Brak pola w `Frame`

Dla pól opcjonalnych, na przykład portów przy ICMP:

- brak pola oznacza `no match` dla bieżącego kroku,
- evaluator przechodzi ścieżką `no_index`,
- brak pola nie kończy całej ewaluacji całej polityki.

To jest wymagana semantyka `RGPF/1`, ponieważ upraszcza ewaluację i lepiej wspiera dalszy rozwój.

## 20. Walidacja `policy.bin`

Przy ładowaniu `policy.bin` firewall powinien sprawdzić co najmniej:

1. `magic`
2. `major/minor`
3. `header_len`
4. `file_len`
5. `file_crc32c`
6. poprawność tablicy sekcji
7. brak nakładania się sekcji
8. spójność offsetów i długości
9. poprawność `RuleNode`
10. poprawność `PatternEntry`
11. poprawność `FieldValue`
12. zgodność `Pattern` z `MatchKind`
13. istnienie dokładnie jednej sekcji `DEFAULT_VERDICT`

Przykłady błędów walidacji:

- `Range(Hour, Hour)` przypięte do `DstPort`,
- `Comparison` dla `IpVer`,
- `Glob` dla typu innego niż `Ip`,
- offset wychodzący poza granice sekcji,
- `root_node_index >= node_count`.

W aktualnej implementacji walidacja obejmuje również:

- CRC32C całego pliku przy wyzerowanym polu `file_crc32c`,
- brak duplikatów wymaganych sekcji,
- pełną walidację `RULE_TREE_TABLE`,
- walidację `NAT_RULE_TABLE`, jeśli sekcja występuje.

## 21. Publikacja rewizji

Ta sekcja opisuje docelowy kontrakt współpracy backendu i firewalla wokół `policy.bin`. Na bieżącej gałęzi zaimplementowane są przede wszystkim firewall-side IPC oraz parser, walidator i loader `RGPF/1`.

### 21.1. Backend

Backend:

1. waliduje konfigurację źródłową,
2. kompiluje `policy.bin`,
3. zapisuje rewizję do katalogu wersjonowanego,
4. atomowo przełącza aktywną rewizję,
5. publikuje identyfikator rewizji i stan przez IPC.

### 21.2. Firewall

Firewall:

1. odczytuje `active/policy.bin`,
2. waliduje plik,
3. buduje politykę wykonywaną w procesie,
4. aktywuje nową politykę,
5. w razie błędu pozostawia poprzednią politykę aktywną.

## 22. MVP

Ta sekcja opisuje stan zaimplementowany na dziś, a nie planowaną pierwszą iterację.

### 22.1. IPC

Gniazda:

- `rg-synchronous.sock`
- `rg-asynchronous.sock`

Wiadomości:

- `PING`
- `GET_STATUS`
- `GET_NETWORK_INTERFACES`
- `HEARTBEAT`

Aktualna implementacja IPC zawiera dodatkowo:

- typowane requesty: `PingRequest`, `GetStatusRequest`, `GetNetworkInterfacesRequest`,
- typowane response: `PingResponse`, `GetStatusResponse`, `GetNetworkInterfacesResponse`,
- typowany event: `HeartbeatEvent`,
- wspólne trait-y wiadomości: `IpcMessage`, `IpcRequestMessage`, `IpcResponseMessage`, `IpcEventMessage`,
- `SyncIpcEndpoint` jako dwukierunkowy endpoint request-response,
- `AsyncIpcEndpoint` jako endpoint eventów.

### 22.2. `policy.bin`

Sekcje:

- `STRING_TABLE`
- `RULE_TREE_TABLE`
- `DEFAULT_VERDICT`
- opcjonalnie `NAT_RULE_TABLE`

Obsługiwany model wykonywania:

- obecny `MatchKind`,
- obecny `Pattern`,
- obecny `Verdict`,
- parser i walidator `NAT_RULE_TABLE`,
- loader do obecnego `CompiledPolicy`, który obsługuje dokładnie jedno drzewo reguł filtrowania,
- brak aktywnego załadowania NAT do runtime, mimo że sekcja NAT jest już parsowana i walidowana.

## 23. Najważniejsze decyzje projektowe

IPC:

- dwa gniazda: synchroniczne i asynchroniczne,
- własne ramkowanie,
- wszystkie liczby jako `varint` / `varlong`,
- minimalny zestaw operacji sterujących.

`policy.bin`:

- stała szerokość pól,
- little-endian,
- brak `varint` / `varlong`,
- układ oparty o sekcje i offsety,
- serializacja skompilowanej semantyki polityki, a nie backendowego modelu danych.

## 24. Podsumowanie

Aktualna implementacja repozytorium opiera się na dwóch spójnych elementach:

- `RGIPC/1` jako lekkim lokalnym protokole komunikacji sterującej,
- `RGPF/1` jako binarnej migawce polityki wykonywanej przez firewall.

Po stronie IPC w repo istnieją już działające typowane endpointy synchroniczne i asynchroniczne oraz runtime firewalla korzystający z tych kanałów.

Po stronie `RGPF/1` istnieje już parser zero-copy z walidacją sekcji, loader do aktualnego `CompiledPolicy` oraz obsługa opcjonalnej sekcji `NAT_RULE_TABLE`.

Najważniejsze bieżące ograniczenia implementacyjne są dwa:

- loader filtrowania obsługuje obecnie dokładnie jedno drzewo reguł,
- sekcja NAT jest parsowana i walidowana, ale nie jest jeszcze ładowana do aktywnego runtime NAT.
