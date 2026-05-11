# Conntrack + NAT refactor — plan

Reimplementacja `tcp_session_tracker` i `nat` wzorowana na netfilter
(`linux/net/netfilter/nf_conntrack_*.c`, `nf_nat_*.c`,
`linux/include/net/netfilter/nf_conntrack*.h`,
`linux/include/uapi/linux/netfilter/nf_nat.h`).

## Cel architektoniczny

Jeden moduł trzyma cały stan per-flow (`Conntrack`). NAT jest stateless silnikiem
translacji: czyta i zapisuje pole `nat: Option<NatTransform>` w `ConntrackEntry`,
trzyma globalnie tylko `port_store` i reguły. Conntrack zarządza lifecyclem entry
(create / confirm / expire) i emituje zdarzenia przez `CtObserver` — NAT
subskrybuje i na `on_destroy` zwalnia port.

## Mapa modułu `crates/raptorgate/src/conntrack/` (stan po Faza 1-4)

```
conntrack/
  mod.rs              # deklaracje submodułów + re-eksporty
  tuple.rs            # FlowTuple { src_ip, src_port, dst_ip, dst_port, zone, protocol }
                      # invert dla TCP/UDP/ICMP (ICMP type/code w dst_port)
  entry.rs            # ConntrackEntry, CtStatus bitflags, CtInfo, NatTransform,
                      # reply: Mutex<FlowTuple> (interior mutability dla NAT),
                      # reassembly: Mutex<ReassemblyState>
  table.rs            # Conntrack — DashMap<FlowTuple, TupleSlot>, lookup/process/
                      # confirm/destroy/flush_zone/flush_all, ProcessOutcome,
                      # reap_cursor (round-robin po bucketach)
  config.rs           # ConntrackConfig (sysctl-style knobs) + ReassemblyConfig + ConfigError
                      # validate() — htable_size <= max_entries, gc_interval >= 500ms itd.
  observer.rs         # CtObserver trait + ObserverRegistry — events:
                      # on_new, on_update, on_destroy, on_anomaly, on_payload
                      # AnomalyKind: TcpOutOfWindow, TcpRetransmit, TcpInvalidFlagsInState,
                      # IcmpUnsolicited
                      # DestroyReason: Timeout, Manual, Replaced, Shutdown
  expectation.rs      # ExpectationTable + Expectation, atomic insert_lock,
                      # find bez `?` (stale ID nie ucina lookupu)
  reaper.rs           # background expiry — bucketing 1/64 (REAP_BUCKETS=64),
                      # batch limit (REAP_BATCH_LIMIT=4096), adaptive pressure
  reassembler.rs      # TCP per-direction stream reorder
                      # ReassemblyDirState (next_seq, BTreeMap<seq, Vec<u8>>),
                      # feed() emituje ciągłe chunki, flush() na FIN/RST,
                      # dedup retransmisji, partial overlap cutting
  proto/
    mod.rs            # ProtocolHandler trait, ProtoRegistry,
                      # NewStateError, NewStateOutcome { State, Related }
    tcp.rs            # port nf_conntrack_proto_tcp.c — TCP_TRANSITIONS[2][6][10],
                      # tcp_in_window() z sender state (1:1 z lines 617-667),
                      # parse_options (WSCALE, SACK_PERM, SACK blocks), tcp_sack(),
                      # last_seq/ack/end/win/flags dla retrans, RST validation
                      # (strict + ignore_invalid_rst), TD_FLAG_WSCALE/SACK_PERM
    udp.rs            # nf_conntrack_proto_udp.c — UNREPLIED → ASSURED,
                      # observers.fire_payload() bezpośrednio per datagram
    icmp.rs           # nf_conntrack_proto_icmp.c — Echo/EchoReply, ICMP error
                      # parsuje embedded packet → NewStateOutcome::Related
                      # (parent flow lookup w table.rs::create_new)
  helper/
    mod.rs            # Helper trait, HelperRegistry
    ftp.rs            # PORT/PASV parsing case-insensitive (strip_prefix_ci)
```

**Nieobecne (w pierwotnym planie były, w finalnej impl pomijane):**
- `cleanup.rs` — zrezygnowano. Cleanup przez `CtObserver::on_destroy`.
- `events.rs` — zrezygnowano. Eventy są już w `observer.rs` jako trait method'y.

## Fazy

### Faza 0 — scaffold ✅ DONE

Pusty submodule `crates/raptorgate/src/conntrack/`, podpięcie do `lib.rs` + `main.rs`.

### Faza 1 — TCP state machine ✅ DONE

`proto/tcp.rs` 1:1 z `nf_conntrack_proto_tcp.c`.

| Kernel | Rust |
|---|---|
| `enum tcp_conntrack` (`nf_conntrack_tcp.h:9`) | `enum TcpConntrack` (None/SynSent/SynRecv/Established/FinWait/CloseWait/LastAck/TimeWait/Close/SynSent2) |
| `tcp_conntracks[2][6][TCP_CONNTRACK_MAX]` | `static TRANSITIONS: [[[Transition; 10]; 6]; 2]` |
| `struct ip_ct_tcp` | `TcpProtoState { state, last_dir, retrans, last_index, seen: [TcpDirState; 2] }` |
| `struct ip_ct_tcp_state` | `TcpDirState { td_end, td_maxend, td_maxwin, td_scale, flags, last_seq, last_ack, last_end, last_win, last_wscale, last_flags }` |
| `tcp_in_window()` | `fn tcp_in_window()` — sender state, 4 condy, MAXACKWINDOW |
| `tcp_options()` | `parse_options()` — MSS skip, WSCALE clamp 14, SACK_PERM, SACK blocks |
| `tcp_sack()` | `fn tcp_sack()` — przesuwa receiver.td_end po blocku SACK |

Stary `TcpSessionTracker` jeszcze żyje (Faza 6 delete), pipeline go nie karmi.

### Faza 2 — UDP/ICMP handlers ✅ DONE

`proto/udp.rs` (nf_conntrack_proto_udp.c): stan `UNREPLIED` → `ASSURED`,
timeout 30s, po `ASSURED` (>=2 pakiety reply) → 120s. `fire_payload` per datagram.

`proto/icmp.rs` (nf_conntrack_proto_icmp.c): tuple koduje (id, type<<8|code).
Echo/EchoReply tracked. ICMP error → parsuje embedded packet
(`parse_embedded_inner_tuple`) → zwraca `NewStateOutcome::Related { parent_tuple }`.
`Conntrack::create_new` na Related: lookup parent → emit `Accept { info: Related }`,
nie tworzy nowego entry.

### Faza 3 — Conntrack core + reaper + observers + reassembler ✅ DONE

`table.rs` z `nf_conntrack_core.c`:

```rust
pub struct Conntrack {
    by_tuple: DashMap<FlowTuple, TupleSlot>,
    expectations: Arc<ExpectationTable>,
    proto: Arc<ProtoRegistry>,
    observers: Arc<ObserverRegistry>,
    config: ArcSwap<ConntrackConfig>,
    metrics: ConntrackMetrics,
    next_id: AtomicU64,
    reap_cursor: AtomicU64,
}
```

API: `process(pkt, zone)`, `lookup`, `confirm`, `destroy`, `flush_zone`, `flush_all`,
`register_observer`, `iter_entries`, `find_by_id`, `expectations`, `next_reap_bucket`,
`reload_config`.

`reaper.rs` z `nf_conntrack_gc_work`: tokio task, `gc_interval` (default 5s),
per cycle 1/REAP_BUCKETS (64) buckets po `entry.id % 64`, adaptive jeśli
ratio > 0.9. REAP_BATCH_LIMIT=4096 victims/tick.

**Observers** (zamiast `events.rs`): `CtObserver` trait z metodami
`on_new`/`on_update`/`on_destroy`/`on_anomaly`/`on_payload` (default empty).
Subscriber rejestruje przez `Conntrack::register_observer`.

**Reassembler** (rozszerzenie ponad pierwotny plan): `reassembler.rs` per-direction
TCP stream z reorderingiem (BTreeMap<seq, Vec<u8>>), dedup retransmisji,
partial overlap cutting, limit pamięci (256 KiB/dir default).
TCP handler karmi po `WindowVerdict::InWindow`, flush na FIN/RST,
emit przez `observers.fire_payload(entry, dir, &chunk)`.

**Znany bug**: `Conntrack::new` tworzy własny `ObserverRegistry` (table.rs:81),
handlery TCP/UDP/ICMP dostają inny przez `TcpHandler::new(observers)`.
Bootstrap w `main.rs` rejestruje observer w obu registries jako workaround.
Naprawa wymaga `Conntrack::with_observers(proto, config, observers)` — TODO.

### Faza 4 — pipeline integracja ✅ DONE

Stage'e w `pipeline/wrappers.rs`:

```rust
pub struct ConntrackInStage { pub ct: Arc<Conntrack> }       // lookup + create-if-new
pub struct ConntrackConfirmStage { pub ct: Arc<Conntrack> }  // confirm po pipeline
pub struct L4StateStage { pub flow_stats: Arc<FlowStatsAggregator> } // ML only
```

`PacketContext` (data_plane/packet_context.rs) ma:
- `set_conntrack(entry, info, dir, is_new)`
- `ct() -> Option<&Arc<ConntrackEntry>>`
- `ct_info()`, `ct_direction()`, `ct_is_new()`

Pipeline (bez NAT refactor na razie):

```
Validation → Metrics → LocalOwnership → ConntrackIn → DPI → TlsPort
→ DnsBlocklist → DnsTunneling → DnsEch → IPS → NatPrerouting (stary)
→ L4State → MlAlert → PolicyEval → NatPostrouting (stary) → FtpAlg
→ ConntrackConfirm
```

Bootstrap w `main.rs`: tworzy `ObserverRegistry`, rejestruje TcpHandler/UdpHandler
z observerami, ICMP v4+v6, `Conntrack::new`, `Reaper::spawn`. Fallback z env
`CAPTURE_INTERFACES` gdy `zone_interfaces.json` nie ma `sniffed=true`.

Stary `TcpSessionTracker` żyje równolegle, ale **pipeline nie karmi go pakietami**.
`query_server.rs:141` nadal trzyma referencję — dump TCP sessions zwraca pustkę.
To akceptowane do Faza 6.

**Tymczasowy patch** w `PolicyEvalStage`: brak zone pair → Continue (warn) zamiast
Halt (drop). Dev-only, do rewertu po skonfigurowaniu zones.

### Faza 5 — NAT refactor (NEXT)

Aktualny `data_plane/nat/`:
- `engine.rs` (647 LOC) — `NatEngine` z **lokalnym stanem**: `bindings: BindingTable`,
  `port_store: PortStore`, `nat_rules`, `interface_ips`. Sam robi cleanup
  (`expire_old_bindings`).
- `bindings/binding_table.rs` — own DashMap<binding_id, NatBinding> + indeksy
  forward/reply.
- `types/nat_binding.rs` — pełen `NatBinding` z 4 tuple'ami (orig_fwd, trans_fwd,
  orig_reply, trans_reply), `expires_at`, `last_seen`.
- `types/flow_tuple.rs` — własny `FlowTuple` (różny od `conntrack::tuple::FlowTuple`).

Restruktura:

```
nat/
  config.rs            # NatConfig + NatRules (slim)
  engine.rs            # NatEngine — bezstanowy, czyta/zapisuje entry.nat
  range.rs             # NatRange odp. nf_nat_range2
  manip.rs             # enum ManipType { Source, Destination }
  packet.rs            # rewrite + checksum (zostaje bez zmian)
  port_alloc.rs        # PortStore (wydzielony z engine), strategie alokacji
  alg/
    ftp.rs             # parser PORT/PASV (już istnieje, dostosować do entry.nat)
    sip.rs             # opcjonalnie (skip na razie)
  helper_bridge.rs     # NatHelper trait — instaluje expectations w Conntrack
                       # przez `conntrack.expectations().insert(exp)`
  cleanup_observer.rs  # impl CtObserver for NatEngine — on_destroy zwalnia port
  types/
    nat_transform.rs   # rozszerzenie istniejącego NatTransform
```

**`NatTransform`** (rozszerzenie istniejącego w `entry.rs:34`):

```rust
pub struct NatTransform {
    pub rule_id: String,
    pub binding_id: u64,
    pub manip: ManipMask,                  // bitflag: SRC | DST
    pub src_manip: Option<TupleManip>,
    pub dst_manip: Option<TupleManip>,
    pub allocated_port: Option<u16>,       // z port_store
    pub allocated_ip: Option<IpAddr>,      // dla NETMAP
}
pub struct TupleManip {
    pub ip: IpAddr,
    pub port: Option<u16>,
}
```

Migracja: aktualny `NatTransform { rule_id, binding_id, allocated_port }` to
podzbiór nowego — pola opcjonalne, nieużywane = `None`.

**`NatEngine` slim:**

```rust
pub struct NatEngine {
    rules: ArcSwap<NatRules>,
    port_store: parking_lot::Mutex<PortStore>,
    interface_ips: ArcSwap<HashMap<String, Vec<IpAddr>>>,
    config: ArcSwap<NatConfig>,
}

impl NatEngine {
    pub fn prerouting(&self, pkt: &mut [u8], ct: &Arc<ConntrackEntry>, info: CtInfo) -> NatOutcome;
    pub fn postrouting(&self, pkt: &mut [u8], ct: &Arc<ConntrackEntry>, info: CtInfo, out_iface: &str) -> NatOutcome;
}

impl CtObserver for NatEngine {
    fn on_destroy(&self, entry: &ConntrackEntry, _reason: DestroyReason) {
        // Release port + binding gdy ct umiera.
        if let Some(transform) = entry.nat.lock().clone() {
            if let Some(port) = transform.allocated_port {
                if let Some(ip) = transform.allocated_ip {
                    self.port_store.lock().delete(ip, /* proto */, port);
                }
            }
        }
    }
}
```

Algorytm `nf_nat_setup_info` (tylko dla NEW; idempotencja przy retransmit SYN):

1. `entry.nat.lock().is_some()` → tylko apply (nie wybieraj nowego portu).
2. Znajdź regułę → wygeneruj `NatRange`.
3. Analog `nf_nat_l4proto_unique_tuple`: szukaj wolnej (ip, port) w range.
   Sprawdź kolizję w `port_store` AND w `conntrack.lookup(reply_tuple)`.
4. Strategia portów (`nf_nat_proto.c`):
   - `PERSISTENT` (default): `hash(src_ip, dst_ip)` → pierwszy kandydat.
   - `RANDOM`: random offset.
   - `RANDOM_FULLY`: pełen random per próba.
5. Zapisz `transform` w `entry.nat`. Set `IPS_SRC_NAT_DONE` / `IPS_DST_NAT_DONE`
   (już istnieją jako `CtStatus::SRC_NAT_DONE`, `DST_NAT_DONE`).
6. Update reply tuple: `entry.set_reply_tuple(entry.original.invert().apply(transform))`
   (wymaga `FlowTuple::apply(transform) -> FlowTuple` helper).

Pipeline z NAT refactor:

```
... LocalOwnership → ConntrackIn → NatPrerouting (nowy) → DPI → ... → IPS
→ L4State → MlAlert → PolicyEval → NatPostrouting (nowy) → Alg → ConntrackConfirm
```

**`NatPreroutingStage`** (nowy):
- `is_applicable`: `ctx.ct().is_some()`
- `process`: `engine.prerouting(pkt, ct, info)`. Outcome modyfikuje pakiet
  in-place przez `apply_translation`.

**`AlgStage`** współpraca z NAT: helper FTP parsuje payload (już ma DPI context),
buduje `Expectation` z `nat_hint` (kopia parent ct.nat),
`conntrack.expectations().insert(exp)`. Gdy data channel SYN wchodzi →
`ConntrackInStage` znajduje exp → tworzy entry RELATED z preinstalled `nat`.
Wymaga: `Helper::install_expectation(entry, payload, dir, conntrack)` zamiast
zwracania `Vec<Expectation>`.

**Bootstrap w `main.rs`**:

```rust
let nat_engine = Arc::new(NatEngine::new(rules, interface_ips, config));
ct_observers.register(Arc::clone(&nat_engine) as Arc<dyn CtObserver>);
conntrack.register_observer(Arc::clone(&nat_engine) as Arc<dyn CtObserver>);
```

**Migracja kroki:**

1. **`port_alloc.rs`**: wyciągnij `PortStore` z `bindings/port_store.rs`,
   thread-safe (Mutex). API: `alloc(ip, proto, range, strategy) -> Option<u16>`,
   `release(ip, proto, port)`.
2. **`NatTransform`** w `entry.rs`: rozszerz o `manip`, `src_manip`, `dst_manip`,
   `allocated_ip`. Backwards-compat: stare pola zostają.
3. **`NatEngine` bezstanowy**: usuń `bindings: BindingTable`, dodaj read/write
   `entry.nat`. `process_prerouting`/`process_postrouting` dostają `&Arc<ConntrackEntry>`.
4. **`impl CtObserver for NatEngine`**: `on_destroy` release portu.
5. **`NatPreroutingStage`/`NatPostroutingStage`** zaktualizowane sygnatury (ct
   z PacketContext).
6. **`FtpAlgStage`** używa `conntrack.expectations()` zamiast lokalnego rejestru.
7. **Stary `BindingTable`** zostaje do Faza 6 jako shim (puste DashMap, `lookup`
   zawsze None) — żeby `query_server.rs:141 nat_engine.bindings_iter()` nie
   wybuchło. Po Faza 6 delete.

**Property test**: 10k pakietów PCAP przez stary i nowy path, porównanie
verdict + outbound IP/port per flow. Różnica > 0 = bug.

### Faza 6 — usunięcie starego kodu

Po przejściu testów na nowym path:

- DELETE `data_plane/tcp_session_tracker.rs` (logika w `conntrack/proto/tcp.rs`).
- DELETE `nat/bindings/binding_table.rs`, `types/nat_binding.rs`,
  `types/flow_tuple.rs` (własny FlowTuple).
- DELETE `pipeline/wrappers.rs::TcpClassificationStage` (już nieużywany).
- Update `query_server.rs:141` — `tcp_tracker` → `conntrack.iter_entries()`.
  API endpoint dump entries.
- Update events i frontend kontrakty (gRPC/WebSocket schema).
- Naprawa bug'a: `Conntrack::with_observers(proto, config, observers)` — jeden
  registry współdzielony. Usuń workaround z main.rs (rejestracja w 2 miejscach).
- Revert dev fallback w `PolicyEvalStage` (no zone pair → drop zamiast Continue)
  po skonfigurowaniu zones.

## Konfiguracja eksponowana frontendowi

### Globalne — Conntrack

| Setting | Zakres | Default | Kernel | Frontend |
|---|---|---|---|---|
| `max_entries` | 1024..16M | 262144 | `nf_conntrack_max` | slider+input |
| `htable_size` | 1024..1M | 65536 | `nf_conntrack_buckets` | input |
| `gc_interval` | 500ms..60s | 5s | `nf_conntrack_gc_work` | input |
| `log_invalid` | none/all/tcp/... | none | `nf_conntrack_log_invalid` | dropdown |
| `accounting` | bool | false | `nf_conntrack_acct` | toggle |
| `timestamp` | bool | false | `nf_conntrack_timestamp` | toggle |
| `events_enabled` | bool | true | `nf_conntrack_events` | toggle |
| `tcp.loose` | bool | true | `nf_conntrack_tcp_loose` | toggle |
| `tcp.be_liberal` | bool | false | `nf_conntrack_tcp_be_liberal` | toggle |
| `tcp.ignore_invalid_rst` | bool | false | `nf_conntrack_tcp_ignore_invalid_rst` | toggle |
| `tcp.max_retrans` | 1..255 | 3 | `nf_conntrack_tcp_max_retrans` | input |
| `tcp.timeout.syn_sent` | 1..3600 | 120 | `nf_conntrack_tcp_timeout_syn_sent` | input |
| `tcp.timeout.syn_recv` | 1..3600 | 60 | `nf_conntrack_tcp_timeout_syn_recv` | input |
| `tcp.timeout.established` | 60..432000 | 432000 | `nf_conntrack_tcp_timeout_established` | input |
| `tcp.timeout.fin_wait` | 1..3600 | 120 | jw. | input |
| `tcp.timeout.close_wait` | 1..3600 | 60 | jw. | input |
| `tcp.timeout.last_ack` | 1..3600 | 30 | jw. | input |
| `tcp.timeout.time_wait` | 1..3600 | 120 | jw. | input |
| `tcp.timeout.close` | 1..600 | 10 | jw. | input |
| `tcp.timeout.max_retrans` | 60..1800 | 300 | jw. | input |
| `tcp.timeout.unacknowledged` | 60..1800 | 300 | jw. | input |
| `udp.timeout` | 1..600 | 30 | `nf_conntrack_udp_timeout` | input |
| `udp.timeout_stream` | 1..3600 | 120 | `nf_conntrack_udp_timeout_stream` | input |
| `icmp.timeout` | 1..600 | 30 | `nf_conntrack_icmp_timeout` | input |
| `generic.timeout` | 1..3600 | 600 | `nf_conntrack_generic_timeout` | input |
| `reassembly.enabled` | bool | true | (extension) | toggle |
| `reassembly.max_buffered_bytes` | 4096..16M | 262144 | (extension) | input |
| `reassembly.max_segment_size` | 1500..65535 | 65536 | (extension) | input |

### Globalne — NAT

| Setting | Zakres | Default | Kernel | Frontend |
|---|---|---|---|---|
| `port_range.start` | 1024..65535 | 40000 | `ip_local_port_range` | dual slider |
| `port_range.end` | 1024..65535 | 60000 | jw. | jw. |
| `port_alloc_strategy` | persistent/random/random_fully | persistent | `NF_NAT_RANGE_PROTO_RANDOM*` | radio |
| `port_collision_retry` | 1..128 | 16 | `nf_nat_l4proto_unique_tuple` | input |
| `masquerade_address_change_handling` | flush/keep | flush | `nf_nat_masquerade.c` | radio |
| `helpers_enabled` | multi-select | [ftp] | per-helper module | checkbox list |
| `expectation.max_per_helper` | 1..1024 | 256 | `nf_conntrack_expect_max` | input |
| `expectation.max_total` | 1024..16384 | 4096 | jw. | input |
| `expectation.timeout` | 30..3600 | 300 | per-helper | input |

### Globalne — Performance

| Setting | Default | Frontend |
|---|---|---|
| `defrag.enabled` | true | toggle |
| `defrag.timeout` | 30s | input |
| `defrag.max_per_flow` | 64 | input |
| `pipeline.checksum_verify` | true | toggle |
| `reaper.batch_limit` | 4096 | input |
| `reaper.adaptive_threshold` | 0.9 | slider |

### Lokalne (per reguła NAT)

- `id`, `priority`, `enabled`
- `action`: SNAT / DNAT / MASQUERADE / PAT / NETMAP
- `in_interface` / `out_interface` / `in_zone` / `out_zone`
- `src_cidr` / `dst_cidr`
- `src_port` / `dst_port`
- `protocol` (TCP/UDP/ICMP/all)
- `translated_ip` / `translated_port` / `translated_port_range`
- `range_flags` (`PERSISTENT`, `RANDOM`, `RANDOM_FULLY`, `NETMAP`)
- `helper`: none/ftp/sip
- `mark` / `zone`

### Lokalne (per zone)

- `zone_id` (u16)
- `direction_scope`: original / reply / both (`NF_CT_ZONE_DIR_*`)
- `conntrack_isolation`: bool

### Live monitoring (read-only)

- Lista aktywnych entries (paginacja, filtry: zone/proto/state).
- Live event stream (NEW/UPDATE/DESTROY/RELATED/ANOMALY/PAYLOAD) — WebSocket
  przez `CtObserver` mostek do gRPC/WS.
- Per-entry actions: `flush`, `reset_counters`, `force_close` (TCP RST inject).
- Pool utilization: % `port_store` per `(ext_ip, proto)` — alarm gdy >85%.
- Top talkers (jeśli accounting on).
- Reassembly buffer usage per flow (debug).

### Frontend struktura panelu

```
Settings
├── Conntrack
│   ├── Global limits
│   ├── Features
│   ├── TCP behavior
│   ├── Timeouts (TCP/UDP/ICMP/Generic)
│   └── Reassembly
├── NAT
│   ├── Port allocator
│   ├── Masquerade
│   └── Helpers
├── Rules (NAT)
├── Zones
└── Live (Entries / Events / Pool utilization)
```

### API kontrakt

```
GET  /api/v1/conntrack/config
PUT  /api/v1/conntrack/config
GET  /api/v1/nat/config
PUT  /api/v1/nat/config
GET  /api/v1/nat/rules
POST /api/v1/nat/rules
PUT  /api/v1/nat/rules/{id}
DEL  /api/v1/nat/rules/{id}
GET  /api/v1/conntrack/entries
DEL  /api/v1/conntrack/entries/{id}
DEL  /api/v1/conntrack/entries
WS   /api/v1/conntrack/events
GET  /api/v1/nat/pool/usage
```

### Walidacja UI

- `port_range.end > port_range.start`, `end - start >= 1024`.
- `htable_size <= max_entries`.
- `tcp.timeout.established >= tcp.timeout.fin_wait`.
- `gc_interval >= 500ms`.
- `reassembly.max_buffered_bytes >= 4096`.
- Zmiana `htable_size` = full rebuild → ostrzeżenie o spadku wydajności.
- Zmiana `port_range` z aktywnymi bindingami → ostrzeżenie o starych mappingach.

### Persistent storage

Sekcje w `AppConfig`: `conntrack: ConntrackConfig`, `nat: NatConfigExt`.
Reload przez `ConfigObserver`. `Conntrack::reload_config(cfg) -> Result<(), ConfigError>`
i `NatEngine::reload_config(cfg)` implementują trait.

## Ryzyko per faza

| Faza | Status | Risk | Mitigation |
|---|---|---|---|
| 0 | ✅ DONE | low | Tylko nowy submodule |
| 1 (TCP SM) | ✅ DONE | medium | Tested 145+ unit tests |
| 2 (UDP/ICMP) | ✅ DONE | low | Greenfield |
| 3 (Conntrack core + reaper + observers + reassembler) | ✅ DONE | medium | Reaper bucketing tested; obs registry bug znany |
| 4 (Pipeline integracja) | ✅ DONE | high | Dev test na vagrant: TCP/UDP/HTTP curl działa |
| 5 (NAT refactor) | NEXT | high | Property test stary vs nowy path; FTP ALG e2e |
| 6 (cleanup + bug fixes) | TODO | low | Delete dopiero po 2 tyg. zielonych |

## Otwarte rzeczy do dokończenia (Faza 6 lub osobno)

1. `Conntrack::with_observers(proto, config, observers)` — naprawa workaround'u
   z main.rs (jeden registry zamiast dwóch).
2. Zone pair config dla VM testowej (revert dev fallback w PolicyEvalStage).
3. Frontend → conntrack toggle `sniffed=true` dla interfejsów (zamiast
   env CAPTURE_INTERFACES fallback).
4. DPI refactor jako `CtObserver` konsument zamiast własnego `DashMap<FlowKey, ...>`.
5. `ConntrackEntry::reassembly` opcjonalnie inicjalizowany leniwie (oszczędność
   dla UDP/ICMP).
6. `tcp_session_tracker.rs` delete + `query_server` przepisany na conntrack iter.

Total scope dla Faza 5: ~2-3 tyg dla 1 dewelopera.
