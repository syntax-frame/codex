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
 *                   emitted once just before done; persist it per node).
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
 *   ctx           opaque pointer forwarded to every callback invocation.
 *   callback      invoked for each streamed event (see codex_event_callback).
 */
void codex_run_turn_streaming(const char *access_token,
                              const char *id_token,
                              const char *account_id,
                              const char *model,
                              const char *prompt,
                              const char *history_json,
                              void *ctx,
                              codex_event_callback callback);

#ifdef __cplusplus
}
#endif

#endif /* CODEX_IOS_H */
