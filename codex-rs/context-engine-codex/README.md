# Codex Context Adapter

This crate translates between the current Codex `ResponseItem` and rollout
formats and `codex-context-engine`. It is an extraction scaffold, not a new
persistence authority.

`codex-core` can run the adapter as a non-authoritative prompt parity check by
setting `CODEX_CONTEXT_ENGINE_SHADOW=1`. The shadow path receives the already
prepared request history, round-trips it through the portable contract, and
logs aggregate classifications only. It cannot alter or block a turn. It is
not enabled by default and is not wired into AgentApp Next storage.

## Mapping policy

- User, assistant, developer, and system messages become semantic messages.
- Image and audio URLs must resolve to application-owned attachment IDs. Raw
  URLs and data URLs never become permanent portable context.
- Plain inter-agent messages retain routing and trigger-versus-queue delivery
  semantics. Encrypted inter-agent messages remain opaque.
- Local shell, function, and custom tool records become portable tool records.
- Reasoning, hosted web/tool search, hosted image generation, native
  compaction, additional-tool state, and unknown response variants remain
  exact opaque JSON bound to the supplied provider lineage.
- Request controls and rollout-only runtime/presentation records are returned
  as explicit ignored classifications rather than silently discarded.
- Compacted replacement history becomes either a semantic checkpoint or a
  lineage-bound native checkpoint when any replacement item is opaque.
- Portable messages and local/function/custom tool records can be reconstructed
  for the current typed Codex request path.
- Provider-opaque records require an exact lineage match. Known records retain
  their original JSON beside the typed value; unknown future records fail the
  typed path closed until a raw request transport can carry them unchanged.
- Application-owned image and audio attachments are materialized only while
  preparing a provider request. Provider URLs and data URLs are not written
  back into portable message history.

Callers should supply original response JSON whenever it is available. It is
required for unknown future response variants and whenever canonical
serialization would omit an in-memory provider field.

## Cutover blockers

- Semantic Codex response-item IDs and internal chat metadata are not yet
  represented by the portable contract. The shadow comparison intentionally
  normalizes those fields; a live authority must preserve any fields required
  for continuation.
- Image detail is not yet represented by the portable attachment record.
- Structured function/custom tool outputs can contain provider-facing media.
  Those outputs need attachment normalization before they can be committed to
  an application-owned context store.
- Unknown future opaque records need a raw request transport. The current typed
  `ResponseItem` request path rejects them rather than silently losing state.
- AgentApp Next still needs a transactional GRDB `ContextStore` implementation
  and migration before this adapter may own resume, fork, or compaction state.
