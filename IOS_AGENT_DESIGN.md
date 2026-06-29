# Codex-iOS Agent — Living Design Document

**Status:** Draft / exploratory
**Last updated:** 2026-06-29
**Base:** fork of `openai/codex` (Rust agent core) at `~/projects/codex`
**Goal:** a Codex-derived agentic coding assistant that runs natively on iPhone.

> This is a **living document**. It will change. Section 0 tracks decisions and
> open questions; everything below is the current best plan, not a contract.

---

## 0. Decision log & status

| Date | Decision |
|---|---|
| 2026-06-29 | Fork Codex (Rust) as the agent core; it cross-compiles to iOS natively. |
| 2026-06-29 | **Brain on-device, hands remote.** Loop/client/reasoning run on the phone; shell/builds run on a remote machine over SSH (an ordinary tool). |
| 2026-06-29 | **Drop `spawn_tree` and `reparent` from the agent toolset.** Children inherit the ability to spawn their own children → trees emerge organically. Reparenting becomes a manual UI action later, not a tool. |
| 2026-06-29 | **Keep Codex's "agent" vocabulary** (`spawn_agent`, `wait_agent`, …). Add our verbs as `agent_*`. Do NOT rename to `child_*` — keeps us mergeable with upstream. |
| 2026-06-29 | **Reuse Codex's tool-gating as our permission system.** `ToolExposure` + the gated `add_*` assembly already model "not all tools available every turn, per agent." |
| 2026-06-29 | **Drop our experimental plan-gating.** Adopt Codex's `update_plan` instead. |
| 2026-06-29 | **De-risk in three independent tracks** (see §2). iOS-viability first, using the existing OpenAI provider and ~zero tools. |
| 2026-06-29 | **Durable scheduler lives on the server**, app woken via push. iOS cannot run 30-day in-app timers. |
| 2026-06-29 | **✅ M0 ACHIEVED.** `codex-api` cross-compiled clean for iOS (device+sim). New `codex-ios` FFI crate (`codex_run_prompt`) packaged as `CodexIOS.xcframework`. SwiftUI app (`~/projects/codex-ios-app`) signed (team V2KMP9T8PA), installed on physical iPhone 17 Pro Max, and got a **real `gpt-5.4` reply over the ChatGPT OAuth backend** ("Hello from an iPhone today."). Key unlocks: pinned toolchain 1.95.0 needed the iOS target; static-lib xcframework modulemap conflicts → use a **bridging header** (drop bundled modulemap); ChatGPT backend gates Codex models on the **`originator: codex_cli_rs`** header; model slug must be current (`gpt-5.4`). OAuth token reused from `~/.codex/auth.json` (temporary; on-device login is next). |

**Open questions:** see §9.

### Convergence decisions (2026-06-29, after reviewing `~/AgentApp`)

The real integration target is **`~/AgentApp`** (a working SwiftUI app): Metal-rendered notes graph with child-spawning nodes + per-node conversations, chat bubbles with roles (`.user`/`.assistant`/`.thinking`/`.remembering`), `TextRevealController` token-paced reveal, Kokoro TTS fed off the live stream, Whisper STT, `ConversationStore` (local DB). Its current `NodeAgent.swift` is a **hand-rolled FoundationModels (Apple on-device) fixed-workflow pseudo-loop** (summarize → N thinking passes → maybe 1 tool `create_child_node` → answer). That hand-rolled loop was a throwaway experiment.

- **The Codex turn loop fully REPLACES the hand-rolled loop.** One loop drives everything. The Apple on-device model, if retained, becomes just *one provider option behind the Codex loop* — not its own loop.
- **Per-node model/provider selection is the goal.** Each graph node picks a specific `{provider, model}` (Apple on-device, OpenAI, Moonshot, …). The loop is instantiated per-node with `{provider, model, auth}` at call time.
- **History across model switches:** store each node's history in the **provider-neutral IR** (`ResponseItem`: messages + tool calls + results) and translate at the provider edge per turn. Conversational history carries across a model switch; **reasoning continuity does NOT** (OpenAI encrypted CoT / Anthropic thinking signatures are provider-specific) — switching a node's model preserves history, drops in-flight reasoning state. Acceptable boundary; design the store around it.
- **AgentApp's bubble roles map 1:1 onto the Codex event stream** (`reasoning`→`.thinking`, `text`→`.assistant`, tool events→new tool bubble). The UI is already shaped for this.
- **Integration discipline:** build Codex core as a clean `CodexCore` framework with a streaming event API; prove it in the throwaway smoke app FIRST; then slot it into AgentApp **behind `NodeAgent`'s seam** — do NOT gut the working app in place.

---

## 1. Vision

A native iPhone app that is a full agentic coding assistant. The **agent brain**
(Codex's Rust turn loop, model client, history & reasoning handling) runs
on-device. Capabilities iOS forbids — running a shell, building, testing — are
**delegated to a remote machine over SSH as ordinary tools**. Because all heavy
compute (LLM inference + command execution) is remote, the app is a **thin,
lightweight head**: a fat agent on a slim client.

Multi-agent from the start: an agent can spawn child agents, each with its own
local working directory (scratch/notes/memory) and, when needed, its own remote
workspace.

---

## 2. Thesis & the three risks

**Thesis:** Codex's Rust turn loop compiles to iOS and runs a full agentic loop
on-device *unchanged*; OS-forbidden capabilities are delegated over the network
as normal tools, so the loop never needs to know the difference.

Three **independent** risks. Attack them separately — never bundle them:

| # | Risk | Where to prove it | When |
|---|---|---|---|
| 1 | Does the Rust loop build & run on iOS at all? | physical iPhone, existing OpenAI provider, ~zero tools | **FIRST** |
| 2 | Multi-provider adapter (Moonshot / Anthropic) | **desktop** (Codex already builds & runs there) | parallel, separate |
| 3 | SSH remote-hands (real shell work) | desktop sim first, then device | after #1 |

The MVP (§8, M1) targets **only risk #1**.

---

## 3. Architecture

```
            ┌─────────────────────────  iPhone (thin client)  ──────────────────────────┐
            │                                                                            │
            │   Swift UI shell  ◄──FFI──►   Codex core (Rust, xcframework)               │
            │   - chat view                 - turn loop (run_turn)        UNCHANGED      │
            │   - notifications             - model client (HTTPS)                       │
            │   - per-agent workdir         - history / reasoning                        │
            │     (app container)           - tool router                                │
            │                               - local tools: update_plan, notes, files     │
            │                               - ssh_exec tool ─────────────┐               │
            └─────────────────────────────────────────────────────────── │ ──────────────┘
                          │ HTTPS                                         │ SSH (russh)
                          ▼                                               ▼
                 ┌──────────────────┐                        ┌────────────────────────┐
                 │  LLM provider    │                        │  Remote machine        │
                 │  (Responses API; │                        │  (Atlas / VPS / VM)    │
                 │  later Moonshot, │                        │  - real shell, builds  │
                 │  Anthropic, …)   │                        │  - the actual codebase │
                 └──────────────────┘                        │  - durable scheduler   │
                                                             └────────────────────────┘
```

- **Brain (on-device):** Codex `core` turn loop + model client + history/reasoning, compiled to `aarch64-apple-ios`, packaged as an `xcframework`, driven by a thin Swift UI.
- **Model (remote):** LLM over HTTPS. Start with Codex's existing OpenAI Responses path. Other providers are a separate workstream (§2 risk #2).
- **Hands (remote):** shell/build/test on a server via an `ssh_exec` tool (pure network, `russh` — no subprocess, iOS-legal).
- **Local tools:** notes / plan / file scratch inside the app container; each agent gets its own working directory.
- **Multi-agent:** agents spawn child agents (capability inherited); trees emerge organically; reparenting is a later manual-UI action, not a tool.

### 3.1 What runs where

| Concern | On-device | Remote |
|---|---|---|
| Turn loop / reasoning | ✅ | |
| LLM inference | | ✅ (API) |
| Shell / build / test | | ✅ (SSH) |
| Project files | | ✅ (server) |
| Notes / plan / scratch | ✅ (container) | |
| Durable scheduling | trigger/receive only | ✅ (cron/queue) |
| Image gen / print | | ✅ (your APIs) |

---

## 4. Tool plan

Source of truth for Codex's existing tools: the inventory in this repo's analysis.
Our tools map onto Codex in three buckets.

### ① Already in Codex → extend
| Our tool | Codex equivalent | Add |
|---|---|---|
| spawn agent | `spawn_agent` | local working dir, lifetime/TTL, role, model, permission flags |
| agent send | `send_message` / `send_input` | — |
| agent info | `list_agents` | per-agent detail |
| agent delete | `close_agent` / `interrupt_agent` | — |
| (wait / interrupt) | `wait_agent`, `interrupt_agent` | free upgrade — we didn't have these |
| generate image | `image_generation` (hosted) | repoint at local ComfyUI |
| plan | `update_plan` | adopt as-is; drop our experimental plan-gating |

### ② New but trivial
- `message_user` / `send_file` — async notify (iOS local/push notification + UI). Codex's `request_user_input` is blocking Q&A, not this.
- `print_file` — wrapper on the printer API.
- `agent_rename` — cosmetic.
- `agent_access` — toggle a descendant's `canMessageUser` (a permission flip).
- `agent_set_model` — per-agent model override.

### ③ New, real work
- **`agent_extend`** (lifecycle/TTL) — Codex agents have no ephemeral/lifetime concept. Adds expiry, warnings, persistent vs ephemeral.
- **Durable scheduler** (`schedule_wakeup` / `list_wakeups` / `cancel_wakeup`) — see §6.

**Dropped:** `spawn_tree`, `reparent` (organic trees + manual UI instead).

### Permissions
Reuse Codex's gating. Add our dimensions as gates in the per-turn assembly:
`canMessageUser`, `canSchedule`, `canGenerateImages`, `canPrint`, `userChatMode`.
No new permission subsystem — it's a config layer on `ToolExposure` + `add_*`.

### Naming
Keep **`agent`** as the noun. Our verbs: `agent_extend`, `agent_set_model`,
`agent_access`, `agent_rename`. Parent/child is the *relationship*, already
implied by `spawn_agent`.

---

## 5. Scheduler (server-backed, push-woken)

Codex's `clock/sleep` is a **blocking in-process sleep** — cannot schedule far
out, blocks the turn. Ours is **durable**: persists, survives restarts, fires a
*fresh turn* into the session later. Different capability class.

iOS cannot run reliable 30-day in-app timers, so:
- **The schedule store + timer live on the server** (cron/queue on the SSH box or a small backend).
- When a wakeup fires, the server **pushes** (APNs silent/visible) to wake the app, which then runs the scheduled turn.
- On-device piece = "register intent" + "receive wake". Same SSH-server pattern that solves the shell also solves scheduling.

---

## 6. iOS execution model & constraints

**Can:** full compute in foreground; local notifications; push (APNs); background
URLSession (completes while suspended); best-effort `BGTaskScheduler` (minutes,
OS-scheduled, not guaranteed).

**Cannot:** run arbitrary code indefinitely in background; guarantee long timers;
spawn subprocesses; JIT.

**Design consequence:** keep the app **lightweight** (no local LLM, no local
shell). Long/continuous work happens on the server; the app is woken by push to
check in and render. A thin client survives iOS background limits; a fat one
would not.

---

## 7. Build & packaging

- Targets: `aarch64-apple-ios` (device), `aarch64-apple-ios-sim` (sim).
- Package Rust core as an `xcframework`.
- FFI boundary: **UniFFI** (preferred for a clean Swift API) vs `swift-bridge` — decide in M0.
- **The real M0 hurdle:** Codex `core` likely has hard compile-time deps on the
  exec/sandbox crates (Seatbelt / Landlock / subprocess). These won't build for
  iOS. First task = **feature-gate them out** so loop + client + history compile
  clean for the iOS target. This is the long pole of M0.
- App distribution: TestFlight (account + API key already configured on this machine).

---

## 8. Milestone roadmap

> **MVP = M1.** Everything before it is plumbing; everything after is additive.

- **M0 — Smoke / build proof.** Carve an iOS-buildable `core` (feature-gate out
  exec/sandbox). Rust core → xcframework → trivial Swift app that calls in and
  renders **one non-streaming model reply**. Proves FFI + build + link + network.
  *No loop, no tools.*

- **M1 — Loop on device (THE MVP).** Full turn loop, streaming, with **exactly
  one on-device tool** firing (`update_plan` or a local-note tool) and feeding
  back into the loop, on a **physical iPhone**, using the **existing OpenAI
  provider**. *No shell, no SSH, no provider work.* Proving this proves the thesis.

- **M2 — Remote hands.** Add `ssh_exec` (russh). Agent does real shell work on a
  server. `apply_patch` rides over SSH.

- **M3 — Multi-agent.** `spawn_agent` + per-agent local workdir + messaging;
  inherited spawn capability; child remote-workspace isolation when needed.

- **M4 — User-facing + permissions.** `message_user`/notifications, `send_file`,
  the permission gating dimensions.

- **M5 — Durable scheduler.** Server-backed wakeups + push (§5).

- **M6 — Provider adapter.** Moonshot / Anthropic. **Developable on desktop in
  parallel from M1** — independent of the iOS track (§2 risk #2).

- **M7 — Polish.** Image gen (ComfyUI), print, lifecycle/TTL, UI reparenting.

---

## 8.1 Carve scoping result (2026-06-29)

Probed `cargo build -p codex-core --target aarch64-apple-ios-sim`. Findings:
- **Shell/sandbox/exec crates COMPILE for iOS** as inert shells — Codex `#[cfg]`-gates platform code to `macos`/`linux`/`windows`, none of which is `ios`. They build; the dead code never runs (fine — we cut those tools). `linux-sandbox`/`bwrap`/`process-hardening` aren't even core deps.
- **The ONE hard blocker: V8**, via `codex-code-mode`, pulled in by `codex-tools` (near-universal dep). rusty_v8 ships no iOS prebuilt. Build compiled ~60 crates then died only on V8.
- **Fix:** make `codex-code-mode` an **optional cargo feature** (`code-mode`, default-on); `#[cfg]`-gate its modules + registration (`spec_plan.rs:201, 530-539`). Risk = whether code-mode types leak into shared signatures (`ToolRouter`) → could turn days into a week. Spike running to measure.
- **Loop is already per-node parameterizable:** `{provider, model, auth}` in `TurnContext`/`Session`, per-turn, **zero global state**. Concurrent multi-model nodes need no refactor.
- **Effort verdict: days, not weeks** (gated by the code-mode cut). Next risks after V8: `codex-network-proxy` (`rama-unix` on iOS-unix-family), `security-framework` macos-only gap.
- **Recommended approach:** a `core`/`tools` cargo feature (`mobile`/`no-code-mode`), NOT a wrapper crate (V8 enters via shared `codex-tools`, so it must be cut at the feature level).

## 8.2 Carve spike result (2026-06-29, branch `ios-mobile-feature`)

- **V8 excised from the iOS graph.** Made `codex-code-mode` an optional `code-mode` cargo feature (default-on). Build now clears every crate (incl. all sandbox/exec crates) and only errors on residual code-mode refs in `core`.
- **The #1 feared risk did NOT materialize.** Codex already splits V8 (`codex-code-mode`) from a V8-free `codex-code-mode-protocol` crate. `codex-tools` + `codex-rollout-trace` used ONLY protocol symbols → swapped to depend on the protocol crate directly (no feature flag, no `ToolRouter`/public-API cascade). **`ToolRouter`/registry: untouched.**
- Cut went **21 → 10 errors**, all the hard ones (protocol-type redirects) done. Remaining 10 are mechanical: gate two `Arc<dyn CodeModeSessionProvider>` struct fields in `Session`/`ThreadManager` + `CodeModeService` + registration calls.
- **Desktop build stays green** (code-mode default-on).
- **Refined estimate: ~1 day** to a compiling iOS `core`. Next blocker to probe past core: `codex-network-proxy`/`rama-unix`.
- **Feature structure:** `codex-core` `default = ["code-mode"]`; mobile builds `--no-default-features`. Permanently move `codex-tools`/`codex-rollout-trace` to `codex-code-mode-protocol` (strict win for desktop too).
- Status: finishing the last 10 errors to get `core` compiling for both iOS targets, committing to `ios-mobile-feature`.

## 9. Open questions

1. Default SSH target — Atlas? A dedicated VPS? Per-user config?
2. APNs / push setup — needs Apple push entitlement + a tiny push backend.
3. FFI choice — UniFFI vs swift-bridge (decide in M0).
4. How deeply do exec/sandbox crates thread through `core`? Determines M0 effort.
5. Where do agent secrets (API keys, SSH keys) live on-device — Keychain + Secure Enclave?
6. Offline behavior — what (if anything) works with no network / no server?
7. Reasoning continuity on non-OpenAI providers (M6) — the known hard part from the coupling analysis.
