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

#ifdef __cplusplus
}
#endif

#endif /* CODEX_IOS_H */
