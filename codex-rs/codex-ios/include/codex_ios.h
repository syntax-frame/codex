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
 * Free a string previously returned by codex_run_prompt().
 * Passing NULL is a no-op.
 */
void codex_free_string(char *s);

/*
 * Streaming event callback for codex_run_turn_streaming().
 *   ctx         opaque pointer passed through verbatim from the call site.
 *   event_kind  0 = reasoning delta, 1 = text delta, 2 = done, 3 = error,
 *               4 = history (full updated rollout as a JSON array of ResponseItems,
 *                   emitted once just before done; persist it per node),
 *               5 = tool call, as JSON {"tool": <name>, "args": <value>},
 *               6 = reasoning section break (start a new thinking bubble),
 *               7 = dynamic tool call — the turn is PAUSED until the client
 *                   replies via codex_respond_dynamic_tool(). Payload is JSON
 *                   {"turn_handle": <uint64>, "call_id": <string>,
 *                    "tool": <string>, "namespace": <string|null>,
 *                    "arguments": <value>}.
 *   text        NUL-terminated UTF-8, valid ONLY for the duration of the call;
 *               copy it if it must outlive the callback.
 */
typedef void (*codex_event_callback)(void *ctx, int event_kind, const char *text);

/*
 * Drive ONE user turn through the REAL Codex turn loop (run_turn) and stream
 * events to `callback`. Blocks until the turn completes. Talks to the ChatGPT
 * OAuth backend.
 *
 * All string args are NUL-terminated UTF-8 C strings:
 *   access_token  OAuth bearer access token.
 *   id_token      OAuth id token (JWT) — required to load ChatGPT auth.
 *   account_id    ChatGPT account id.
 *   model         Model slug, e.g. "gpt-5.4".
 *   prompt        The user prompt.
 *   history_json  Prior conversation rollout as a JSON array of ResponseItems
 *                 (from a previous turn's history event), or NULL/empty for a
 *                 fresh conversation. Gives the model memory across turns.
 *   workspace_path  Absolute path to the node's working directory; the turn is
 *                 rooted here so file tools operate inside it. NULL/empty = none.
 *   ctx           opaque pointer forwarded to every callback invocation.
 *   callback      invoked for each streamed event (see codex_event_callback).
 */
void codex_run_turn_streaming(const char *access_token,
                              const char *id_token,
                              const char *account_id,
                              const char *model,
                              const char *prompt,
                              const char *history_json,
                              const char *workspace_path,
                              void *ctx,
                              codex_event_callback callback);

/*
 * Generic API-key counterpart of codex_run_turn_streaming(): drive ONE user
 * turn against ANY OpenAI-Responses-compatible endpoint using a plain bearer
 * API key instead of ChatGPT OAuth. Use for OpenAI proper (with an API key), a
 * local Ollama / LM Studio server, or any paid compatible provider. Same
 * streaming/callback contract and event kinds as codex_run_turn_streaming().
 * Local mode only (shell/exec disabled, on-device file tools).
 *
 * All string args are NUL-terminated UTF-8 C strings (null/empty as noted):
 *   base_url        Provider API root exposing the Responses API at
 *                   "<base_url>/responses" (e.g. "http://localhost:11434/v1"
 *                   for a local Ollama, or "https://api.openai.com/v1").
 *   api_key         Sent as "Authorization: Bearer <api_key>". For a local
 *                   server that ignores auth, any non-empty placeholder works.
 *   model           Model slug, e.g. "granite4.1:8b" or "gpt-5.4".
 *   prompt          The user prompt.
 *   history_json    Prior conversation rollout as a JSON array of ResponseItems,
 *                   or NULL/empty for a fresh conversation.
 *   workspace_path  Absolute path to the node's working directory; the turn is
 *                   rooted here so file tools operate inside it. NULL/empty = none.
 *   ctx             opaque pointer forwarded to every callback invocation.
 *   callback        invoked for each streamed event (see codex_event_callback).
 */
void codex_run_turn_streaming_apikey(const char *base_url,
                                     const char *api_key,
                                     const char *model,
                                     const char *prompt,
                                     const char *history_json,
                                     const char *workspace_path,
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
 *   id_token        OAuth id token (JWT) — required to load ChatGPT auth.
 *   account_id      ChatGPT account id.
 *   model           Model slug, e.g. "gpt-5.4".
 *   prompt          The user prompt.
 *   history_json    Prior conversation rollout as a JSON array of ResponseItems,
 *                   or NULL/empty for a fresh conversation.
 *   workspace_path  Absolute path to the working directory ON THE SERVER; the
 *                   turn is rooted here (must exist on the remote host).
 *                   NULL/empty = none.
 *   ssh_host        Remote SSH host (hostname or IP).
 *   ssh_port        Remote SSH port (e.g. 22).
 *   ssh_user        Remote SSH username.
 *   ssh_key_pem     OpenSSH PRIVATE KEY CONTENTS (PEM text), NOT a path. Written
 *                   to a chmod-600 temp file for the duration of the call and
 *                   deleted afterward; never persisted.
 *   ssh_fingerprint Expected server host-key fingerprint in OpenSSH "SHA256:..."
 *                   form. When NULL or empty, host-key pinning is disabled
 *                   (any host key accepted). When set, the connection is
 *                   rejected unless the server's host key matches.
 *   ctx             opaque pointer forwarded to every callback invocation.
 *   callback        invoked for each streamed event (see codex_event_callback).
 */
void codex_run_turn_streaming_server(const char *access_token,
                                     const char *id_token,
                                     const char *account_id,
                                     const char *model,
                                     const char *prompt,
                                     const char *history_json,
                                     const char *workspace_path,
                                     const char *ssh_host,
                                     uint16_t ssh_port,
                                     const char *ssh_user,
                                     const char *ssh_key_pem,
                                     const char *ssh_fingerprint,
                                     void *ctx,
                                     codex_event_callback callback);

/*
 * Resolve an in-flight dynamic tool call (event_kind 7): deliver the client's
 * result back to the PAUSED turn identified by turn_handle so it can resume.
 * Call this exactly once per event_kind-7 callback, passing the same
 * turn_handle and call_id carried in that event's JSON payload.
 *
 *   turn_handle    the "turn_handle" from the dynamic-tool-call payload.
 *   call_id        the "call_id" from the dynamic-tool-call payload.
 *   response_json  NUL-terminated UTF-8 JSON object {"text": <string>,
 *                  "success": <bool>} (both optional: text defaults to "",
 *                  success to true). Wrapped into the tool output the model sees.
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
