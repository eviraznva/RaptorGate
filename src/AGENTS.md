# Dla agenta:
- Nie próbuj reformatować części kodu, których nie modyfikujesz
- Nie dodawaj komentarzy, chyba że dany fragment kodu jest w normalnych warunkach nieoczekiwany / używane jest unsafe

Prowadzony aktualnie jest rework kilku aspektów firewalla. Zapoznaj się z wymaganiami
# Rework:
## Processing pakietów

Zasada polega na chainowaniu warstw processingu. Każda warstwa przyjmuje referencje do pakietu wrappowanego w context. Każda wartstwa implementuje trait `Stage`:
```rust
pub trait Stage: Send + Sync {
    fn is_applicable(&self, ctx: &PacketContext) -> bool { true }
    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome;
}
pub enum StageOutcome { Continue, Halt }
```

Packet context zawiera sam pakiet i info potrzebne do ustalenia dalszego processingu albo jakieś drogie operacje jakie wypada cacheować.
```rust
pub struct PacketContext {
    pub raw:        Vec<u8>, // albo SlicedPacket, jeśli kompilator nie będzie krzyczał
    pub iface:      String,

    pub warnings:   Vec<String>,

    pub flags: PacketFlags,

    pub dpi_result:      OnceLock<Option<DpiResult>>,
    pub radius_identity: OnceLock<Option<RadiusIdentity>>,
    pub transport:  OnceLock<Option<TransportInfo>>,
    ...
}
```

Pakiet też może mieć flagi, które może odczytywać i modyfikować każda warstwa. Wtedy np. DPI może sprawdzać czy pakiet jest w sesji i skipować głęboką analizę, zależy od configa:
```rust
bitflags::bitflags! {
    pub struct InspectionFlags: u8 {
        const DPI_BLOCKED  = 0b00000001;
        const SSL_INSPECT   = 0b00000010;
        const ML_ANALYSIS   = 0b00000100;
        const IS_IN_ESTABILISHED_SESSION = 0b00001000;
        ...
    }
}

```
Jest szansa, że to skomplikuje działanie wszystkiego, bo efektywnie wprowadza to stanowość z flagami, które musimy sprawdzać, ale sprawdzenie takiej flagi jest o wiele szybsze niż na przykład odczytywanie czegoś z mapy, więc przydałoby się to do jakiś hot spotów. Może by się to dało ogarnąć jakimiś setterami i getterami, które wymuszają ustawienie i odczyt flagi przy odczycie jakiejś właściwości.

Wszystkie warstwy łączy się w `Chain`, ruska rzecz, tak wygląda:
```rust
pub struct Chain<A: Stage, B: Stage> { head: A, tail: B }
impl<A: Stage, B: Stage> Stage for Chain<A, B> {
    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let outcome = if self.head.is_applicable(ctx) {
            self.head.process(ctx).await
        } else {
            StageOutcome::Continue
        };
        match outcome {
            StageOutcome::Continue => self.tail.process(ctx).await,
            StageOutcome::Halt     => StageOutcome::Halt,
        }
    }
}
type DataPlanePipeline =
    Chain<ParseStage,
    Chain<ValidationStage,
    Chain<NatPreroutingStage,
    Chain<PolicyEvalStage,
    Chain<TcpTrackingStage,
    Chain<NatPostroutingStage,
          TunForwardStage>>>>>>; // przykladowe

```

Razem z  zależnościami, deklaruje się to tak:
```rust
let policy_store = Arc::new(PolicyStore::new(...));
let tcp_tracker  = Arc::new(TcpSessionTracker::new());
let nat_engine   = Arc::new(NatEngine::new(...));
let tun          = Arc::new(setup_tun(...).await);
let handler = FirewallQueryHandler {
    policy_store: Arc::clone(&policy_store),
    tcp_tracker:  Arc::clone(&tcp_tracker),
    nat_engine:   Arc::clone(&nat_engine),
};
let pipeline = Chain {
    head: PolicyEvalStage  { policies: &*policy_store },
    tail: Chain {
        head: TcpTrackingStage { tracker: &*tcp_tracker },
        tail: // ...
    }
};
```
Nadal są rzeczy w Arcach, bo handlowanie requestów z serwera potrzebuje `'static`. Sam pipeline działa na zwykłych referencjach. Zwykłe singletony nie są używane bo je trudno mockować.

## Eventy / Co z backendem

Z eventami mamy 2 kwestie:
- Eventy jakie firewall pushuje na backend, np. jakieś alerty. Rzecz bazuje na typie z protobufa:
```protobuf
message Event {
    google.protobuf.Timestamp emitted_at = 1;
    oneof kind {
        PolicyDrop    policy_drop    = 2;
        NatBinding    nat_binding    = 3;
        ConfigChanged config_changed = 4;
        ...
    }
}
```
Z perspektywy kodu mielibyśmy funkcję `emit`:
```rust
static EVENT_SEND: OnceLock<mpsc::Sender<EventSerialized>> = OnceLock::new();
pub fn emit(event: Event) {
    if let Some(tx) = EVENT_SEND.get() {
        if tx.try_send(event.into()).is_err() {
            tracing::warn!("event queue full, event dropped");
        }
    }
}
```

Gdzie `Event` to typ który jest używany w domenie. Każdy wariant powinien się serializować do `EventSerialized`, który jest generowany z proto. Nie ma biblioteki do automatycznej serializacji, więc trzeba pisać własne.
```rust
pub struct Event {
    pub emitted_at: SystemTime,
    pub kind:       EventKind,
}
pub enum EventKind {
    PolicyDrop     { src: IpAddr, dst: IpAddr, reason: String },
    NatBinding     { binding_id: u64, rule_id: String },
    TcpSession     { src: IpAddr, dst: IpAddr },
    PolicyDropWarn { src: IpAddr, dst: IpAddr, reason: String },
    ConfigChanged  { version: u64 },
    ...
}

impl From<Event> for EventSerialized {
    fn from(event: Event) -> EventSerialized {
        EventSerialized {
            emitted_at: Some(prost_types::Timestamp {
                seconds: event.emitted_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64,
                nanos:   event.emitted_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().subsec_nanos() as i32,
            }),
            kind: Some(match event.kind {
            EventKind::PolicyDrop { src, dst, reason } => EventSerializedKind::PolicyDrop(EventPolicyDrop {
                src: src.to_string(),
                dst: dst.to_string(),
                reason,
            }),
            EventKind::NatBinding { binding_id, rule_id } => EventSerializedKind::NatBinding(EventNatBinding {
                binding_id,
                rule_id,
            }),
            ... // tutaj idą wszystkie typy
            }),
        }
    }
}
```

Jest jeszcze kwestia czy dany event można batchować, czy nie, to można rozwiązać funkcją, która matchuje po każdym wariancie `EventKind` i odpowiednio wybiera. 

- Requesty backendu. Jakkolwiek firewall może pushować eventy do serwera i nie obchodzi go co serwer z nimi zrobi, to serwer powinien requestować firewalla jeżeli czegoś chce i oczekiwać od niego odpowiedzi. `tonic`, czego już używamy pozwala na zrobienie serwera `gRPC` na firewallu:
```rust
Server::builder()
    .timeout(Duration::from_secs(5))
    .layer(AuthLayer::new()) // layery to właściwie middleware
    .add_service(FirewallQueryServer::new(handler)) //
    .serve_with_incoming(UnixListenerStream::new(listener))
    .await?;
```

Serwisy poiwnny być definiowane w proto:
```protobuf
service FirewallQueryService {
    rpc GetTcpSessions (GetTcpSessionsRequest)  returns (GetTcpSessionsResponse);
    rpc ValidateConfig (ValidateConfigRequest)  returns (ValidateConfigResponse);
    rpc GetNatBindings (GetNatBindingsRequest)  returns (GetNatBindingsResponse);
}
```

 Biblioteka generuje traity z serwisów, więc pozostaje je zaimplementować:
 ```rust
#[derive(Clone)]
pub struct QueryHandler { // na to właśnie potrzebne są Arc<>
    tcp_tracker:  Arc<TcpSessionTracker>,
    nat_engine:   Arc<NatEngine>,
    policy_store: Arc<PolicyStore>,
}
#[tonic::async_trait]
impl FirewallQueryService for QueryHandler {
    async fn get_tcp_sessions(
        &self,
        request: Request<GetTcpSessionsRequest>,
    ) -> Result<Response<GetTcpSessionsResponse>, Status> { ... }
    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> { ... }
    async fn get_nat_bindings(
        &self,
        request: Request<GetNatBindingsRequest>,
    ) -> Result<Response<GetNatBindingsResponse>, Status> { ... }
}
```

## Logowanie / Eventy / Ostrzeżenia

### Ostrzeżenia

- `ctx.warnings: Vec<String>` na `PacketContext` akumuluje ostrzeżenia w trakcie przetwarzania
- Warstwy pushują ostrzeżenia przed zwróceniem `Continue` lub `Halt` — brak rozróżnienia na poziomie warstwy
- `AllowWarn` / `DropWarn` zostają **izolowane w silniku polityk** i nie wychodzą do systemu typów pipeline'u. `PolicyEvalStage` tłumaczy je:
  - `AllowWarn` → `Continue` + push do `ctx.warnings`
  - `DropWarn` → `Halt` + push do `ctx.warnings`
- Emisja ostrzeżeń następuje w **pętli pakietów po powrocie `pipeline.process()`**, gdzie `ctx.verdict` jest ostateczny:
  - `Allow` → emituj ostrzeżenia jako allow warnings (log + event do backendu)
  - `Drop` → emituj ostrzeżenia jako deny warnings (log + event do backendu)
  - Zapobiega to emisji allow warnings dla pakietów później odrzuconych przez kolejną warstwę

### Logowanie

Dwa poziomy, każdy należy do innej warstwy:

- **Logi obserwacyjne** (`tracing::trace/debug`) — emitowane wewnątrz funkcji pomocniczych gdzie dana rzecz się dzieje, niezależnie od wyniku. Np. nawiązanie sesji TCP loguje się tam, nie w `process`.
- **Logi wynikowe** (`tracing::warn/error`) — emitowane w `process` gdy błąd mapuje się na `Halt`, bo tam znany jest wynik i dostępny jest pełny `PacketContext`.

Brak duplikacji — każdy poziom loguje inne rzeczy na innym poziomie abstrakcji.

### Eventy

Ten sam podział co logowanie:

- **Eventy domenowe** (`TcpSessionEstablished`, `NatBindingCreated`) — emitowane wewnątrz funkcji która je tworzy, bezwarunkowo. Są to fakty o tym co się wydarzyło, niezależne od wyniku pipeline'u.
- **Eventy wynikowe** (odrzucony pakiet, ostrzeżenia jako eventy) — emitowane w pętli pakietów po powrocie chain'u, używając ostatecznego `ctx.verdict` + `ctx.warnings`. Nigdy nie emitowane w środku pipeline'u dla pakietów na ścieżce allow, bo verdict nie jest jeszcze ostateczny.

### `StageOutcome`

- Warstwy które chcą przekazać kontekst o halcie pushują do `ctx.warnings` przed zwróceniem
- Warstwy które haltują cicho (zniekształcony pakiet, zły checksum) po prostu zwracają `Halt` bez pushowania czegokolwiek
- Obecność lub brak `ctx.warnings` wystarczy do rozróżnienia "ma coś do powiedzenia" od "cichy drop"
- `HaltReason` enum dla granularności metryk odłożony do czasu zaprojektowania właściwego systemu metryk

## Inspekcja DNS

Trzymamy listę domen zblacklistowanych jako drzewo podzielone na poziomy domeny.


