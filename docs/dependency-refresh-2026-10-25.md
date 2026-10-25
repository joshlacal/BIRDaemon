# BIRDaemon dependency refresh — 25 October 2026

BIRDaemon is Catbird's encrypted-chat bot. This refresh updates its Rust dependencies and reconciles the daemon with the current shared MLS core and generated chat contract. The work preserves account data and the existing bridge reply policy. It does not qualify a live account, remote delivery, or production startup.

## Protocol and transport

Chat operations use prepared method/path/body requests through the admitted Nest session. The adapter preserves the raw status, content type, and response bytes so the shared core can interpret signed-protocol errors. Unauthorized responses invalidate only the matching authority snapshot, including delayed failures after an account/session change. PDS repository helpers continue to require a bearer session; a DPoP or delegation token is not treated as a bearer.

The active subscription sends two DAG-CBOR values per frame: a header and a generated `blue.catbird.chat.defs#eventEnvelope` or `typingEvent`. The transport decodes the generated inner value, retains union discriminators, and invokes the shared core's strict subscription parser. Unknown types, trailing data, and over-bound frames fail explicitly.

Every connection uses `prepare_subscription()` to apply fresh authenticated inventories and mint their exact one-use ticket. `initialize_subscription_cursor()` installs the corresponding durable fence before opening the WebSocket. `apply_subscription_frame()` validates the previous-cursor chain, catches up canonical conversation entries, applies verified state, ensures durability, and advances the fence with compare-and-swap. Only a successful returned outcome is dispatched to the bot's reply handler. The transport neither guesses a resume cursor nor acknowledges failed processing.

The existing reply policy is unchanged: live messages returned by the shared core are sent to the local bridge backend. Current-epoch messages caught up during reconnect are persisted by inventory synchronization but are not replayed as LLM replies. This work does not add an offline reply queue or promise recovery of every old-epoch application message.

## Storage and compatibility

SQLite integer conversion remains checked after rusqlite removed direct unsigned bindings. Values above `i64::MAX` and negative stored values fail, rather than wrapping. `DeviceRemoved` and `Closed` conversation states remain terminal across local persistence. The existing legacy conversation rows have no canonical-state JSON column; the shared MLS core retains canonical authority separately.

Legacy trait operations that have no canonical wire equivalent remain explicit errors, including raw KeyPackage lookup/hash reconciliation and the old Welcome getter. They do not fabricate successful responses. The current shared canonical inventory/Welcome path owns any supported admission and acknowledgement flow.

## Reproducible verification

Use the pinned toolchain from `rust-toolchain.toml`:

```sh
rustup run 1.99.1 cargo test --locked --all-targets
rustup run 1.99.1 cargo clippy --locked --all-targets
rustup run 1.99.1 cargo fmt --check
./scripts/check-canonical-sibling-provenance.sh
cargo audit
```

The provenance command retains its historical filename for callers. The guard checks Cargo's resolved core dependency (either the canonical sibling repository or immutable Git revision), its complete enabled feature set (`[]`), the sealed commit `48f8adcaa0c18cd211ba2545581fca4a8ec175b0`, clean working tree state, and the tracked lockfile hash. The previous machine-specific receipt is retained under `scripts/provenance-baselines/` and is not represented as current evidence.

Loopback tests exercise the actual HTTP/WebSocket transport with local fixtures and no accounts. They cover target validation, raw error preservation, session invalidation, generated frame decoding, fresh ticket/cursor encoding, failed processing without dispatch, and duplicate-frame rejection. These fixtures are separate from the shared core's native cursor/storage tests and do not establish live MLS decryption or bridge replies.

The audited graph retains three unsuppressed maintenance warnings through shared dependencies: `audiopus_sys` (`RUSTSEC-2026-0150`), `basic-toml` (`RUSTSEC-2026-0374`), and `proc-macro-error2` (`RUSTSEC-2026-0173`). The last is present in the all-target dependency graph, not the current macOS target tree. A normal bot launch reads real configuration and credentials from the user's Application Support directory; it was not used for these checks.
