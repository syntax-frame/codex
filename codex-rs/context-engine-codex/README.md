# Codex Context Adapter

This crate translates the current Codex `ResponseItem` and rollout formats
into `codex-context-engine`. It is an extraction scaffold and is not wired into
`codex-core`, `codex-ios`, or AgentApp Next yet.

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

Callers should supply original response JSON whenever it is available. It is
required for unknown future response variants and whenever canonical
serialization would omit an in-memory provider field.
