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

The provenance command retains its historical filename for callers. The guard checks Cargo's resolved core dependency (either the canonical sibling repository or immutable Git revision), its complete enabled feature set (`["default","labyrinth"]`: catbird-mls enables Labyrinth by default), the pinned commit in `scripts/canonical-sibling-provenance.env` (currently the Task 4 R4 fork-readd follow-up `85d25801a538d82c85d11213d4aafaef213afa58`), clean working tree state, and the tracked lockfile hash. CI checks out catbird-mls, catbird-atproto and labyrinth at the exact commits recorded in that file. The previous machine-specific receipt is retained under `scripts/provenance-baselines/` and is not represented as current evidence.

The bot transport never turns a refused connection, timeout or other network failure into an HTTP response: it returns an error and makes one attempt per call, so a request whose effect is unknown is not resent behind the core's back. Before every home-DS XRPC request it mints a fresh PDS service-auth JWT for the exact `{homeDsDid}#atproto_mls` audience and request NSID, then checks its issuer, audience, `lxm`, current expiry (no more than 60 seconds ahead) and optional `nbf`. A non-success mint response, unreadable body, malformed JSON, missing token, invalid claim, or network failure aborts before any DS bytes are sent; the PDS OAuth/session token is never used as DS authorization. Real DS responses, including 5xx, pass through unchanged for the core's transient/terminal classification and journaled retry.
Only an ES256 JWT can pass this claim gate; symmetric and unsigned service tokens are refused.

Production transport accepts only HTTPS URLs. It resolves each host, rejects loopback, private, link-local, multicast and unspecified addresses (including IPv4-mapped IPv6 forms), disables environment proxies and redirects, and pins the validated address set into the one-request client so DNS cannot change between validation and connection. HTTP loopback is available only through explicit `*_for_test` constructors compiled by `cfg(any(test, feature = "test-support"))`; `test-support` is non-default, and the default constructors remain strict even when that feature is present.
Shared, benchmarking, documentation, transition and reserved ranges are non-public and refused as well.

The transport attaches the PDS bearer only to the configured PDS endpoint and the freshly minted service bearer only to the configured home `mls-ds` endpoint. Endpoints are compared as parsed URLs (scheme, host, port, then the endpoint's path at a `/` boundary), not as string prefixes, so `https://pds.example.evil.com`, another port or a sibling path gets no bearer, and neither does any other host. Caller-supplied `Authorization` is discarded at this boundary rather than bypassing those rules.
Within that endpoint, the PDS bearer is limited to exact `com.atproto.*` XRPC methods; discovery paths remain anonymous and any other XRPC fails closed unless it is classified against the configured home-DS base.

Loopback tests exercise the actual transport with local fixtures and no accounts. They cover feature isolation, refused connections, mint failure classes and exact claims, HTTPS/address refusal, DNS pinning, redirect refusal, and bearer origin/path containment. These fixtures are separate from the shared core's native cursor/storage tests and do not establish a live production account.

With the Task 4 R1 lock, `cargo audit` (advisory database `a7210fc1`, 2026-10-30) finds no vulnerability and six unsuppressed maintenance warnings, all through shared dependencies: `atomic-polyfill` (`RUSTSEC-2023-0089`, via `postcard`), `audiopus_sys` (`RUSTSEC-2026-0150`), `basic-toml` (`RUSTSEC-2026-0374`), `bincode` (`RUSTSEC-2025-0141`, via `uniffi_macros`), `paste` (`RUSTSEC-2024-0436`, via `uniffi`) and `proc-macro-error2` (`RUSTSEC-2026-0173`). A normal bot launch reads real configuration and credentials from the user's Application Support directory; it was not used for these checks.
