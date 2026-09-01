#ifndef CODEX_IOS_H
#define CODEX_IOS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Perform a single OpenAI Responses API round-trip.
 *
 * All arguments are NUL-terminated UTF-8 C strings:
 *   access_token  OAuth bearer token (sent as "Authorization: Bearer <token>").
 *   account_id    ChatGPT account id (sent as the "ChatGPT-Account-ID" header).
 *   model         Model slug, e.g. "gpt-5-codex" or "gpt-5".
 *   prompt        The user prompt.
 *
 * Returns a newly malloc'd, NUL-terminated UTF-8 C string containing the
 * model's text reply, or a string beginning with "ERROR: " on failure.
 * The caller owns the returned pointer and must release it with
 * codex_free_string().
 */
char *codex_run_prompt(const char *access_token,
                       const char *account_id,
                       const char *model,
                       const char *prompt);

/*
 * Return the live, account-aware Codex model catalog as a JSON array of model
 * presets. The caller owns the result and must release it with
 * codex_free_string(). Errors are returned as strings beginning with "ERROR: ".
 */
char *codex_list_models_json(const char *access_token,
                             const char *id_token,
                             const char *account_id);

/*
 * Resolve the current account's concrete OAuth model and reasoning defaults
 * without starting a turn. Returns typed JSON with `status` equal to
 * `available` or `unavailable`; failures use the normal `ERROR: ` string.
 * The caller owns the result and must release it with codex_free_string().
 */
char *codex_resolve_oauth_defaults_json(const char *access_token,
                                        const char *id_token,
                                        const char *account_id);

/*
 * Free a string previously returned by this library.
 * Passing NULL is a no-op.
 */
void codex_free_string(char *s);

/*
 * Reconcile one persisted server-mode model context without submitting a model
 * prompt. `action` is "recheck" for proof-only inspection or
 * "fence_for_successor" for an explicit proof-bound cancellation before the
 * host creates a fresh successor context.
 *
 * Returns allocated, content-free contract-v1 JSON:
 *   {"contract_version":1,
 *    "status":"recovered"|"still_held"|"terminal_failure"|"fresh_authorized",
 *    "reason":<stable string>}
 * Release the result with codex_free_string().
 */
char *codex_reconcile_persisted_context_server(
    const char *action,
    const char *context_home_path,
    const char *workspace_path,
    const char *ssh_connection_key,
    const char *ssh_session_key,
    const char *ssh_host,
    uint16_t ssh_port,
    const char *ssh_user,
    const char *ssh_auth_method,
    const char *ssh_secret,
    const char *ssh_fingerprint,
    const char *ssh_tmux_mode);

/*
 * Streaming event callback for codex_run_turn_streaming().
 *   ctx         opaque pointer passed through verbatim from the call site.
 *   event_kind  0 = reasoning delta, 1 = text delta, 2 = done, 3 = error,
 *               4 = compatibility history projection containing only the
 *                   latest completed assistant message,
 *               5 = tool call, as JSON {"tool": <name>, "args": <value>},
 *               6 = reasoning section break (start a new thinking bubble),
 *               7 = dynamic tool call — the turn is PAUSED until the client
 *                   replies via codex_respond_dynamic_tool(). Payload is JSON
 *                   {"turn_handle": <uint64>, "call_id": <string>,
 *                    "tool": <string>, "namespace": <string|null>,
 *                    "arguments": <value>},
 *               8 = turn ready for steering; text is the decimal uint64 handle
 *                   to pass to codex_steer_turn(),
 *               9 = the persistent context was compacted,
 *              10 = accumulated thread token/context-window data as JSON,
 *              11 = exact token usage for one completed model response as JSON,
 *              12 = canonical ItemStartedEvent as JSON,
 *              13 = canonical ItemCompletedEvent as JSON,
 *              14 = context compaction started; text is the same canonical
 *                   ItemStartedEvent JSON also emitted through event kind 12,
 *              15 = content-free dynamic-tool discovery lifecycle JSON. It
 *                   never includes search text, schemas, IDs, arguments, or
 *                   tool output. Payload contract version 1 is
 *                   {"contract_version":1,"event":"search_requested"|
 *                   "search_loaded"}. Consumers must ignore unsupported
 *                   versions; older libraries simply never emit kind 15.
 *              16 = turn aborted. This is terminal and is never followed by
 *                   event kind 2 (done) for the same turn.
 *              17 = turn starting. `text` is an interrupt-only handle; the
 *                   same handle becomes steerable only if kind 8 follows.
 *              18 = structured error JSON. Payload contract version 1 is
 *                   {"contract_version":1,"code":<stable string>,
 *                    "message":<string>,"http_status_code":<number|null>,
 *                    "rate_limits":<RateLimitSnapshot|null>}.
 *                   Optional fields are omitted when unavailable. Usage-limit
 *                   errors include the latest matching rate-limit snapshot;
 *                   all other errors omit it. Older libraries emit kind 3.
 *              19 = content-free native startup stage for latency diagnostics.
 *                   Text is a stable stage identifier and never contains
 *                   prompts, tool arguments, credentials, or model output.
 *   text        NUL-terminated UTF-8, valid ONLY for the duration of the call;
 *               copy it if it must outlive the callback.
 */
typedef void (*codex_event_callback)(void *ctx, int event_kind, const char *text);

/*
 * Content-free admission input for the AgentApp-only turn entrypoints.
 * `semantic_request_prompt` is the immutable work prompt used by both
 * generations. `semantic_request_digest` must be the canonical lower-case
 * SHA-256 digest of the versioned request envelope. The generation-specific
 * `model_input_prompt_digest` binds every byte of the exact prompt passed to
 * the guarded entrypoint, including any recovery bootstrap.
 * `execution_request_digest` binds that exact model input plus the exact
 * model-context directory selected for this generation to the immutable
 * semantic digest. Guarded entrypoints independently derive all three digests
 * from their actual arguments and reject a mismatch before creating a
 * receipt. Generation one must retain the semantic digest, but deliberately
 * receives a new execution digest for its verified fresh-context retry.
 * `requested_generation` is 0 for the original call or 1 for its sole
 * automatic retry. The ticket, digest, receipt root, prompt, credentials, and
 * provider errors are never returned by the receipt query.
 */
typedef struct {
    const char *agent_inbox_ticket_id;
    const char *semantic_request_prompt;
    const char *semantic_request_digest;
    const char *model_input_prompt_digest;
    const char *execution_request_digest;
    const char *receipt_root_path;
    uint32_t requested_generation;
} codex_agentapp_turn_admission;

/*
 * Query one receipt without changing it. Returns allocated contract-v1 JSON:
 * {"contract_version":1,"receipt_version":<number>,"state":<stable string>,
 *  "generation":<number>,"digest_match":<bool>}.
 * `state` is one of preparing, persisted_queued, rejected_before_admission,
 * tool_or_side_effect_possible, model_request_possible, admitted, terminal,
 * missing, ambiguous, or unavailable. Release the result with
 * codex_free_string().
 */
char *codex_query_agentapp_turn_admission_receipt(
    const codex_agentapp_turn_admission *admission);

/*
 * Highest payload contract supported for event kind 15. This query is
 * additive: a consumer paired with an older library should treat an absent
 * symbol exactly like version 0 (discovery telemetry unavailable).
 */
uint32_t codex_ios_tool_discovery_contract_version(void);

/*
 * Drive ONE user turn through the REAL Codex turn loop (run_turn) and stream
 * events to `callback`. Blocks until the turn completes. Talks to the ChatGPT
 * OAuth backend.
 *
 * All string args are NUL-terminated UTF-8 C strings:
 *   access_token  OAuth bearer access token.
 *   id_token      OAuth id token retained for ABI compatibility. Authentication
 *                 uses the externally refreshed access token in memory.
 *   account_id    ChatGPT account id.
 *   model         Model slug, e.g. "gpt-5.4".
 *   reasoning_effort  Exact effort advertised by the model catalog, or
 *                 NULL/empty to use that model's live default.
 *   service_tier  "priority" for Fast Mode, "default" for standard service,
 *                 or NULL/empty to leave the service tier unspecified.
 *   prompt        The user prompt.
 *   history_json  Bootstrap conversation as a JSON array of ResponseItems.
 *                 It is injected only when context_home_path has no resumable
 *                 rollout; resumed contexts ignore it.
 *   context_home_path  Absolute private directory dedicated to this node's
 *                 model context. Codex persists and compacts its rollout here.
 *   workspace_path  Absolute path to the node's working directory; the turn is
 *                 rooted here so file tools operate inside it. NULL/empty = none.
 *   dynamic_tools_json  JSON array of dynamic tool specs the client executes
 *                 on-device (each {"type":"function","name":...,"description":...,
 *                 "inputSchema":{...}}). When one is called the turn PAUSES and
 *                 emits event kind 7; reply with codex_respond_dynamic_tool().
 *                 NULL/empty = no dynamic tools. (Same param on all three turn fns.)
 *   uploads_json  Optional JSON array of local files attached to the turn:
 *                 [{"local_path":"...","relative_path":"uploads/file.png"}].
 *                 Supported image files are added to the model input as normal
 *                 prompt images.
 *   ctx           opaque pointer forwarded to every callback invocation.
 *   callback      invoked for each streamed event (see codex_event_callback).
 */
void codex_run_turn_streaming(const char *access_token,
                              const char *id_token,
                              const char *account_id,
                              const char *model,
                              const char *reasoning_effort,
                              const char *service_tier,
                              const char *prompt,
                              const char *history_json,
                              const char *context_home_path,
                              const char *workspace_path,
                              const char *dynamic_tools_json,
                              const char *uploads_json,
                              void *ctx,
                              codex_event_callback callback);

/*
 * AgentApp-only OAuth counterpart that requires `admission`. All leading
 * parameters and callbacks are identical to codex_run_turn_streaming().
 * Core persists the receipt before context resume or work scheduling, writes
 * model_request_possible before provider submission, and permits generation 1
 * only after durable generation-0 rejected_before_admission with a matching
 * digest.
 */
void codex_run_turn_streaming_agentapp(
    const char *access_token,
    const char *id_token,
    const char *account_id,
    const char *model,
    const char *reasoning_effort,
    const char *service_tier,
    const char *prompt,
    const char *history_json,
    const char *context_home_path,
    const char *workspace_path,
    const char *dynamic_tools_json,
    const char *uploads_json,
    const codex_agentapp_turn_admission *admission,
    void *ctx,
    codex_event_callback callback);

/*
 * Generic API-key counterpart of codex_run_turn_streaming(): drive ONE user
 * turn against an API-key endpoint using a plain bearer API key instead of
 * ChatGPT OAuth. Use `wire_api` to select either an OpenAI Responses-compatible
 * endpoint or a Chat Completions-compatible endpoint. Same
 * streaming/callback contract and event kinds as codex_run_turn_streaming().
 * Local mode only (shell/exec disabled, on-device file tools).
 *
 * All string args are NUL-terminated UTF-8 C strings (null/empty as noted):
 *   base_url        Provider API root, e.g. "https://api.openai.com/v1".
 *   api_key         Sent as "Authorization: Bearer <api_key>". For a local
 *                   server that ignores auth, any non-empty placeholder works.
 *   wire_api        "responses" for "<base_url>/responses", or
 *                   "chat_completions" for "<base_url>/chat/completions".
 *   model           Model slug, e.g. "granite4.1:8b" or "gpt-5.4".
 *   reasoning_effort Exact effort value, or NULL/empty for model default.
 *   service_tier    "priority" for Fast Mode, "default" for standard service,
 *                   or NULL/empty to leave the service tier unspecified.
 *   prompt          The user prompt.
 *   history_json    Bootstrap conversation used only for a genuinely new context.
 *   context_home_path Absolute private directory dedicated to this node's model
 *                   context. Codex persists and compacts its rollout here.
 *   workspace_path  Absolute path to the node's working directory; the turn is
 *                   rooted here so file tools operate inside it. NULL/empty = none.
 *   uploads_json    Optional JSON array of local files attached to the turn:
 *                   [{"local_path":"...","relative_path":"uploads/file.png"}].
 *                   Supported image files are added to the model input as normal
 *                   prompt images.
 *   ctx             opaque pointer forwarded to every callback invocation.
 *   callback        invoked for each streamed event (see codex_event_callback).
 */
void codex_run_turn_streaming_apikey(const char *base_url,
                                     const char *api_key,
                                     const char *wire_api,
                                     const char *model,
                                     const char *reasoning_effort,
                                     const char *service_tier,
                                     const char *prompt,
                                     const char *history_json,
                                     const char *context_home_path,
                                     const char *workspace_path,
                                     const char *dynamic_tools_json,
                                     const char *uploads_json,
                                     void *ctx,
                                     codex_event_callback callback);

/* AgentApp-only API-key counterpart with the same receipt contract. */
void codex_run_turn_streaming_apikey_agentapp(
    const char *base_url,
    const char *api_key,
    const char *wire_api,
    const char *model,
    const char *reasoning_effort,
    const char *service_tier,
    const char *prompt,
    const char *history_json,
    const char *context_home_path,
    const char *workspace_path,
    const char *dynamic_tools_json,
    const char *uploads_json,
    const codex_agentapp_turn_admission *admission,
    void *ctx,
    codex_event_callback callback);

/*
 * API-key + server-mode counterpart: provider transport and SSH tool routing
 * are independent. Drives ONE turn against an API-key provider while shell/exec
 * tools run on the configured SSH host. Parameter meanings match
 * codex_run_turn_streaming_apikey() plus the SSH settings documented for
 * codex_run_turn_streaming_server().
 */
void codex_run_turn_streaming_apikey_server(const char *base_url,
                                            const char *api_key,
                                            const char *wire_api,
                                            const char *model,
                                            const char *reasoning_effort,
                                            const char *service_tier,
                                            const char *prompt,
                                            const char *history_json,
                                            const char *context_home_path,
                                            const char *workspace_path,
                                            const char *dynamic_tools_json,
                                            const char *ssh_connection_key,
                                            const char *ssh_session_key,
                                            const char *ssh_host,
                                            uint16_t ssh_port,
                                            const char *ssh_user,
                                            const char *ssh_auth_method,
                                            const char *ssh_secret,
                                            const char *ssh_fingerprint,
                                            const char *ssh_tmux_mode,
                                            const char *uploads_json,
                                            void *ctx,
                                            codex_event_callback callback);

/*
 * AgentApp-only API-key server counterpart. It marks the receipt
 * tool_or_side_effect_possible before any SSH file upload and advances to
 * model_request_possible before model submission.
 */
void codex_run_turn_streaming_apikey_server_agentapp(
    const char *base_url,
    const char *api_key,
    const char *wire_api,
    const char *model,
    const char *reasoning_effort,
    const char *service_tier,
    const char *prompt,
    const char *history_json,
    const char *context_home_path,
    const char *workspace_path,
    const char *dynamic_tools_json,
    const char *ssh_connection_key,
    const char *ssh_session_key,
    const char *ssh_host,
    uint16_t ssh_port,
    const char *ssh_user,
    const char *ssh_auth_method,
    const char *ssh_secret,
    const char *ssh_fingerprint,
    const char *ssh_tmux_mode,
    const char *uploads_json,
    const codex_agentapp_turn_admission *admission,
    void *ctx,
    codex_event_callback callback);

/*
 * Server-mode counterpart of codex_run_turn_streaming(): drive ONE user turn
 * whose shell/exec tools run on a remote host over SSH instead of being
 * disabled. Same streaming/callback contract and event kinds as
 * codex_run_turn_streaming(); same leading parameters, PLUS the SSH connection
 * settings.
 *
 * All string args are NUL-terminated UTF-8 C strings (null/empty handled as
 * noted):
 *   access_token    OAuth bearer access token.
 *   id_token        OAuth id token retained for ABI compatibility.
 *   account_id      ChatGPT account id.
 *   model           Model slug, e.g. "gpt-5.4".
 *   reasoning_effort Exact effort advertised by the model catalog, or
 *                   NULL/empty to use that model's live default.
 *   prompt          The user prompt.
 *   history_json    Bootstrap conversation used only for a genuinely new context.
 *   context_home_path Absolute private directory dedicated to this node's model
 *                   context. It is local app storage even when tools use SSH.
 *   workspace_path  Absolute path to the working directory ON THE SERVER; the
 *                   turn is rooted here (must exist on the remote host).
 *                   NULL/empty = none.
 *   ssh_connection_key Stable saved-profile key used to pool physical SSH
 *                   transports across agents assigned to the same server.
 *   ssh_session_key Stable per-agent key used for its independent tmux session.
 *   ssh_host        Remote SSH host (hostname or IP).
 *   ssh_port        Remote SSH port (e.g. 22).
 *   ssh_user        Remote SSH username.
 *   ssh_auth_method "private_key" or "password".
 *   ssh_secret      Private-key PEM contents or password, according to
 *                   ssh_auth_method. Private keys use an ephemeral chmod-600
 *                   file; passwords are never persisted by the Rust layer.
 *   ssh_fingerprint Expected server host-key fingerprint in OpenSSH "SHA256:..."
 *                   form. When NULL or empty, host-key pinning is disabled
 *                   (any host key accepted). When set, the connection is
 *                   rejected unless the server's host key matches.
 *   ssh_tmux_mode   "required", "preferred", or "disabled". Required is the
 *                   default and preserves remote commands across SSH drops.
 *   uploads_json    Optional JSON array of local files to mirror to the remote
 *                   workspace before the turn starts:
 *                   [{"local_path":"...","relative_path":"uploads/file.png"}].
 *                   Supported image files are also added to the model input as
 *                   normal prompt images.
 *   ctx             opaque pointer forwarded to every callback invocation.
 *   callback        invoked for each streamed event (see codex_event_callback).
 */
void codex_run_turn_streaming_server(const char *access_token,
                                     const char *id_token,
                                     const char *account_id,
                                     const char *model,
                                     const char *reasoning_effort,
                                     const char *service_tier,
                                     const char *prompt,
                                     const char *history_json,
                                     const char *context_home_path,
                                     const char *workspace_path,
                                     const char *dynamic_tools_json,
                                     const char *ssh_connection_key,
                                     const char *ssh_session_key,
                                     const char *ssh_host,
                                     uint16_t ssh_port,
                                     const char *ssh_user,
                                     const char *ssh_auth_method,
                                     const char *ssh_secret,
                                     const char *ssh_fingerprint,
                                     const char *ssh_tmux_mode,
                                     const char *uploads_json,
                                     void *ctx,
                                     codex_event_callback callback);

/* AgentApp-only OAuth server counterpart with the same receipt contract. */
void codex_run_turn_streaming_server_agentapp(
    const char *access_token,
    const char *id_token,
    const char *account_id,
    const char *model,
    const char *reasoning_effort,
    const char *service_tier,
    const char *prompt,
    const char *history_json,
    const char *context_home_path,
    const char *workspace_path,
    const char *dynamic_tools_json,
    const char *ssh_connection_key,
    const char *ssh_session_key,
    const char *ssh_host,
    uint16_t ssh_port,
    const char *ssh_user,
    const char *ssh_auth_method,
    const char *ssh_secret,
    const char *ssh_fingerprint,
    const char *ssh_tmux_mode,
    const char *uploads_json,
    const codex_agentapp_turn_admission *admission,
    void *ctx,
    codex_event_callback callback);

/*
 * Download one regular file from a server-mode agent's SSH workspace to a
 * caller-provided local path. `remote_path` may be workspace-relative or an
 * absolute path that resolves inside `workspace_path`. Canonicalization on the
 * server rejects traversal and symlink escapes. Files larger than `max_bytes`
 * are rejected.
 *
 * Returns an allocated empty string on success or "ERROR: ..." on failure.
 * Release the result with codex_free_string().
 */
char *codex_download_ssh_workspace_file(const char *ssh_host,
                                        uint16_t ssh_port,
                                        const char *ssh_user,
                                        const char *ssh_auth_method,
                                        const char *ssh_secret,
                                        const char *ssh_fingerprint,
                                        const char *workspace_path,
                                        const char *remote_path,
                                        const char *local_path,
                                        uint64_t max_bytes);

/*
 * Inject a user-authored text message into the active regular turn identified
 * by turn_handle. The handle arrives in event_kind 8 and expires when that turn
 * ends. This is same-turn steering, not a new queued turn.
 *
 * Returns 0 when accepted. Non-zero: 1 = bad text pointer, 2 = empty text,
 * 4 = registry lock poisoned, 6 = unknown/finished turn_handle,
 * 7 = the active turn rejected steering.
 */
int codex_steer_turn(uint64_t turn_handle, const char *text);

/*
 * Attachment-aware same-turn steering. `uploads_json` uses the same local_path
 * and relative_path manifest as turn startup. Supported images are submitted
 * as multimodal input; server-mode turns first mirror all files into the SSH
 * workspace. Empty text is accepted when at least one upload is present.
 *
 * Returns the same codes as codex_steer_turn(), plus 8 = invalid upload
 * manifest, 9 = attachment upload failed, and 10 = upload compensation failed
 * after the exact turn rejected steering.
 */
int codex_steer_turn_with_uploads(uint64_t turn_handle,
                                  const char *text,
                                  const char *uploads_json);

/*
 * Interrupt a registered streaming turn. The handle is emitted through event
 * kind 8 before authentication or thread startup begins, so this is safe to
 * call immediately. Repeated calls are idempotent while the handle is
 * registered.
 *
 * Returns 0 when recorded. Non-zero: 4 = internal lock poisoned,
 * 6 = unknown/finished turn_handle, 7 = the active turn rejected interruption.
 */
int codex_interrupt_turn(uint64_t turn_handle);

/*
 * Resolve an in-flight dynamic tool call (event_kind 7): deliver the client's
 * result back to the PAUSED turn identified by turn_handle so it can resume.
 * Call this exactly once per event_kind-7 callback, passing the same
 * turn_handle and call_id carried in that event's JSON payload.
 *
 *   turn_handle    the "turn_handle" from the dynamic-tool-call payload.
 *   call_id        the "call_id" from the dynamic-tool-call payload.
 *   response_json  NUL-terminated UTF-8 JSON object. Text clients may pass
 *                  {"text": <string>, "success": <bool>}. Multimodal clients
 *                  may pass {"content_items": [{"type": "input_text",
 *                  "text": "..."}, {"type": "input_image", "image_url":
 *                  "data:...", "detail": "high"}], "success": <bool>}.
 *                  text defaults to "", success to true.
 *
 * Returns 0 on success. Non-zero: 1 = bad call_id pointer, 2 = bad
 * response_json pointer, 3 = response_json parse failure, 4 = internal lock
 * poisoned, 5 = the turn already ended, 6 = unknown turn_handle.
 */
int codex_respond_dynamic_tool(uint64_t turn_handle,
                               const char *call_id,
                               const char *response_json);

#ifdef __cplusplus
}
#endif

#endif /* CODEX_IOS_H */
