# Context Engine Contract

This crate is the extraction boundary for AgentApp's durable conversation
history and bounded model context. It is intentionally not connected to the
current Codex runtime yet.

Authentication is outside this boundary. OAuth and API keys supply credentials
to provider adapters; they do not select persistence, local tools, or UI state.

## Invariants

- The application transcript is append-only and remains available after model
  compaction.
- The model projection is bounded independently from the transcript.
- A compaction checkpoint atomically replaces only the model projection through
  a known sequence. It never deletes transcript events.
- Provider-owned encrypted reasoning, continuation handles, and hosted-tool
  state are opaque bytes. They are never decoded, rewritten, or printed.
- Opaque items are sent only to their exact adapter-defined lineage. Switching
  provider or to an incompatible model excludes them without deleting them.
- Attachments remain application-owned references. Provider adapters decide how
  supported models receive their bytes.
- Local dynamic tools are independent from authentication and provider choice.
  Hosted tools are finalized from the selected model's capabilities for every
  turn, including after a model swap. An application-owned web-search backend
  is therefore a local dynamic tool, while OpenAI hosted search remains a
  provider-hosted tool. Portable search results may be normalized into a tool
  record; exact hosted continuation state remains an opaque sidecar.
- A fork contains both its visible transcript and compatible model context.
- The storage adapter must commit append, compaction, and fork operations with
  optimistic sequence checks and transactional durability.

## Compatibility oracle

The fixture suite covers text continuation, opaque reasoning, automatic
compaction, image input plus `view_image`, hosted web search, local dynamic
tools, fork/resume, and model switching. These fixtures describe the portable
contract; the existing runtime remains the behavioral oracle during extraction.

| Contract area | Current runtime oracle | Status before extraction |
| --- | --- | --- |
| Text continuation | `core/tests/suite/resume.rs` | Covered |
| Opaque reasoning | `resume_includes_initial_messages_from_reasoning_events`; `context_manager/history_tests.rs` | Covered by Codex `ResponseItem` persistence |
| Compaction | `core/tests/suite/compact_resume_fork.rs`; `session/rollout_reconstruction_tests.rs` | Covered, currently rollout-owned |
| Images / `view_image` | `codex-ios/src/turn_tests.rs`; `context_manager/history_tests.rs` | Covered through provider and local-tool paths |
| Hosted web search | `core/tests/suite/responses_lite.rs`; `sqlite_state.rs` | Provider-specific |
| Dynamic tools | `codex-ios/src/turn_tests.rs`; `sqlite_state.rs` | Covered, currently session metadata-driven |
| Fork / resume | `compact_resume_fork.rs`; `resume.rs` | Covered, currently rollout-owned |
| Model switch | `resume.rs`; `model_runtime_selectors.rs` | Partial: tool finalization must move behind the selected-model adapter |

## Extraction order

1. Keep the existing tests green and add adapters from current `ResponseItem`
   and rollout records to this contract.
2. Move projection and compaction decisions behind this crate while retaining
   current Codex rollout storage.
3. Add the AgentApp GRDB `ContextStore` implementation and make it the sole
   persistence authority.
4. Keep an OpenAI adapter for encrypted reasoning and native compaction, then
   add other provider adapters.
5. Package the proven boundary as a modern 64-bit Apple library. The current
   CodexCore artifact remains pinned until parity is demonstrated.
