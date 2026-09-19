# Encrypted message request policy

BIRDaemon recognizes encrypted introductions separately from ordinary chat messages. A pending introduction stays in the shared native SQLCipher store and does not enter the bridge, typing, attachment-download, or reply paths. The shared MLS engine verifies publication and consent proofs; the bot does not infer acceptance from a WebSocket event or membership alone.

Three optional configuration fields control automatic behavior. All default to false:

| Field | Behavior |
| --- | --- |
| `receiveChatRequests` | Enable the separate request KeyPackage pool and replenish it through the native engine. |
| `acceptChatRequests` | Explicitly opt into receiving requests and perform canonical signed acceptance for verified incoming previews. |
| `replyToAllMessages` | Permit automatic processing only after verified accepted/ready authority, or a positively classified active legacy conversation. |

Receiving alone does not accept or reply. Autoaccept alone does not reply. Disabling receipt disables the capability on the current device; it does not erase retained private keys or unresolved publication intents. Existing ordinary key-pool enrollment is separate.

The bot rechecks authority before the bridge, attachment fetches, typing heartbeats, and sends. A known request that is pending, closed, malformed, or unavailable fails closed. A missing request projection does not establish legacy status: the native store must contain the exact verified legacy policy, and both participants of a legacy direct conversation must be active.

Each automatic effect first records a SHA256-only unique claim bound to the storage owner, conversation, and message. No pending text is copied to the unencrypted `bird.db` database. Duplicate observations and restarts therefore cannot start a second bridge effect for that message. This is at-most-once processing: a crash after the claim can omit a reply, including a crash before the bridge call. Recovering such an omission requires a separately designed idempotent bridge contract; the bot does not retry uncertain external effects.

Local policy, restart, encrypted-storage, transport, and projection tests exercise these boundaries. They do not replace running the bot against the real request acceptance path through Nest with an inert local bridge. No production bot launch or external LLM call is part of this implementation verification.
