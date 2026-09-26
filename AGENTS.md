# elevate-impact-realtime — agent notes

.NET 8 SignalR hub (`/hubs/elevate`) plus a server-to-server fan-out endpoint
(`POST /api/notify`). The rewrite (SvelteKit) is the only notify caller
(`elevate-impact-rewrite/src/lib/server/realtime/notify.ts`).

## §H-4 status: split into H-4a (shipped by this change) and H-4b (OPEN, blocking)

H-4 is **not closed** by the key split alone.

- **H-4a, the notify key split (this change).** Once an environment reaches
  `enforced`, the public browser key can no longer call `/api/notify`. That
  closes arbitrary `MessageReceived`, `MessageDeleted`,
  `ConversationUpdated`, `SamThinking*` and `ReadReceiptReceived` injection
  through notify. It is safe to ship on its own.
- **H-4b, hub identity (OPEN).** The hub still trusts a self-asserted
  `?userId=`. Anyone with the public key can connect as any existing user,
  so the browser key still allows some cross-user push and eavesdropping,
  even in `enforced`. See §H-4b below. Do not record H-4 as closed until
  H-4b ships.

**How to record it (prod_hotfixes_20260926):** mark H-4a shipped per
environment when runbook step 4's proof appears there. Keep H-4 itself
OPEN. Track H-4b as its own change: it needs a root `+layout.server.ts`
edit, the realtime token verifier, and its own
`query → token-or-query → token` rollout. Reaching step 4 in every
environment does **not** close H-4.

**Follow-up tracking.** Until step 4 runs, an environment stays in `legacy`
or `transition`, which is exactly as exposed as before H-4. Nothing in the
code forces the rollout forward. The only signals are the per-request
`H4_LEGACY_NOTIFY_KEY` warning and the boot line
`H4_NOTIFY_AUTH_MODE=legacy|transition`, which is logged at **Warning**
level until the mode is `enforced`. The coordinator tracks steps 2–4 as
explicit, dated follow-up tasks per environment. Do research-platform first
after dev, because its realtime domain is public.

## §H-4a key split

### Why

Until H-4 the service had ONE key, `SIGNALR_API_KEY`. The browser must hold
it to open the hub (`PUBLIC_SIGNALR_KEY` on the web service), and
`/api/notify` accepted the same value. Anyone could read it from the JS
bundle and `POST /api/notify` to push arbitrary `MessageReceived`,
`MessageDeleted`, `ConversationUpdated`, `SamThinking*` (and, on `dev`,
`AttachmentStatusChanged`) events to any `user:<id>` or `conversation:<key>`
group.

### What each credential authorizes now

| Surface | Public key (`SIGNALR_API_KEY` = web `PUBLIC_SIGNALR_KEY`) | Server key (`SIGNALR_SERVER_KEY`) |
|:---|:---|:---|
| Hub connect `/hubs/elevate` (Bearer / `access_token` / `X-Api-Key` / `?apiKey=`) | yes, **as whatever `?userId=` the caller claims** (H-4b) | **no** |
| Hub methods (`JoinConversation`, `LeaveConversation`, `SendTypingIndicator`, `MarkAsRead`, `GetConversationPresence`) | yes. The conversation-key checks compare against the **attacker-chosen** `userId`, so they check consistency only and are not an authorization boundary (H-4b). | n/a |
| `POST /api/notify` | legacy and transition modes only, logging `H4_LEGACY_NOTIFY_KEY` every time; **refused** in enforced mode | yes |
| `GET /api/health` | anonymous | anonymous |

`SendTypingIndicator` and `MarkAsRead` now drop calls for a key that does
not contain the caller's claimed `userId` (`ElevateHub.IsParticipant`).
That only stops a caller from mixing identities within one connection. It
does **not** stop impersonation, because the caller picks the `userId`.

Comparison is SHA-256 then `CryptographicOperations.FixedTimeEquals`
(`Auth/RealtimeKeys.cs`). Hashing first gives FixedTimeEquals equal-length
inputs, so the comparison does not leak key length either. Both configured
and presented keys are **trimmed**, the same as `notify.ts`, so a trailing
newline in a Railway value cannot cause a one-sided 401. The 32-character
minimum is measured after trimming.

`/api/notify` is mapped only through `Hubs/NotifyEndpoint.cs`
(`app.MapNotifyEndpoint(fanOut)`), which runs `NotifyAuth` before the
fan-out that `Program.cs` supplies. `Tests/NotifyEndpointTests.cs` covers it
over HTTP (TestServer) and fails if `Program.cs` maps `"/api/notify"`
directly. The fan-out `switch` stays in `Program.cs`, so the realtime `dev`
branch's `AttachmentStatusChanged` case still merges cleanly.

### Modes (`RealtimeKeys.Mode`, logged at boot as `H4_NOTIFY_AUTH_MODE=<mode>`)

| `SIGNALR_SERVER_KEY` | `SIGNALR_NOTIFY_ACCEPT_PUBLIC_KEY` | Mode | Public key on notify |
|:---|:---|:---|:---|
| unset / blank | unset / blank, or `true` / `1` | `legacy` | accepted + warning (same as pre-H-4 behaviour) |
| unset / blank | `false` / `0` | **boot refused** | the previous (enforced) deployment keeps serving |
| set | `true` / `1` | `transition` | accepted + warning |
| set | `false` / `0` | `enforced` | **refused** |
| set | unset / blank | **boot refused** | the old deployment keeps serving |

Both refusal rows are deliberate: the key and the switch must agree.
- A lone `SIGNALR_SERVER_KEY` write, which is the most likely operator slip,
  fails the deploy instead of silently enforcing while web still sends the
  legacy key.
- Once enforced, anything that blanks realtime's `SIGNALR_SERVER_KEY` (a
  deleted variable, a delete-then-add rotation, or a `${{…}}` reference that
  dangles and renders as the empty string) fails the deploy instead of
  silently falling back to `legacy`, where the browser key would authorize
  `/api/notify` again. Enforced mode fails **closed**. Leaving it is always
  explicit: set the switch to `true` first (step 4 rollback).

Boot refusals (the process throws before listening):
- `SIGNALR_API_KEY` missing or blank.
- `SIGNALR_SERVER_KEY` set and shorter than 32 characters after trimming.
- `SIGNALR_SERVER_KEY` equal to `SIGNALR_API_KEY`.
- `SIGNALR_SERVER_KEY` set while `SIGNALR_NOTIFY_ACCEPT_PUBLIC_KEY` is unset or blank.
- `SIGNALR_NOTIFY_ACCEPT_PUBLIC_KEY=false` (or `0`) while `SIGNALR_SERVER_KEY`
  is unset or blank (`…=false requires SIGNALR_SERVER_KEY`).
- `SIGNALR_NOTIFY_ACCEPT_PUBLIC_KEY` not one of `true/false/1/0`, in any mode.

`railway.toml` sets `healthcheckPath = "/api/health"`, so a deployment that
refuses to boot should fail its healthcheck, and the previous deployment
should keep serving. **This has not been verified on this service.** After
any failed write, confirm the previous deployment is still ACTIVE
(`list-deployments`), and do not assume it.

### Log lines to grep

| Token | Level | Meaning |
|:---|:---|:---|
| `H4_NOTIFY_AUTH_MODE=legacy\|transition\|enforced` | Warning (legacy, transition) or Info (enforced), once at boot | the mode the running process is in |
| `H4_LEGACY_NOTIFY_KEY` | Warning, per request | a notify was authorized with the PUBLIC key; do not close the transition while these continue |
| `H4_SERVER_KEY_NOTIFY_OK` | Info, once per process | the web service is sending the server key |
| `/api/notify refused (mode …, credential public-key\|unknown\|missing)` | Warning, per request | a refused notify. See the triage note below for `public-key` in `enforced` mode. |

**Triage for `credential public-key` refusals in `enforced` mode.** Check the
web logs at the same timestamp first.
- If web logged `SignalR notify: SIGNALR_SERVER_KEY refused (401); retrying
  with legacy SIGNALR_API_KEY` at the same moment, this is **web's own
  fallback**, not an attack. Web's `SIGNALR_SERVER_KEY` does not match
  realtime's (a rotation or typo), so web retried with the public key and
  realtime refused that too. Each such pair is a dropped live event. Fix the
  web value to match realtime.
- A `credential public-key` refusal with no matching web warning means
  someone outside web replayed the browser key.

Doing step 5 removes the ambiguity: once web has no `SIGNALR_API_KEY`, web
can never send the public key.

### Rewrite side

`notify.ts` sends `SIGNALR_SERVER_KEY` when set, else the legacy
`SIGNALR_API_KEY`. If the server key gets a 401 and a distinct legacy key
is configured, it retries once with the legacy key and logs
`SignalR notify: SIGNALR_SERVER_KEY refused (401)`. That makes a misordered
rollout (web before realtime) degrade to legacy behaviour instead of
dropping events. The retry only helps while web still has
`SIGNALR_API_KEY`, which is why step 5 comes last. See
`elevate-impact-rewrite/src/lib/server/realtime/AGENTS.md`.

### Rollout runbook (zero outage)

Services (confirm with Railway `list-services` before writing; names as of
2026-05): **realtime** = `ElevateImpact- Realtime`, **web** =
`elevate-impact`. Every variable write redeploys only the service it
targets, and it redeploys that service's **current branch head**. Before
each write, check that the live deployment's commit equals the branch head,
so you do not ship something unintended.

Branches: prod realtime builds `main`; dev and research-platform realtime
build `dev`. Prod web builds rewrite `main`; dev web builds `dev`;
research-platform web builds `feature/research-platform`.

Generate one server key **per environment**, never shared across
environments: `node -e "console.log(require('crypto').randomBytes(36).toString('base64url'))"`
(48 chars). Never paste key values into chat, logs, tickets or commit
messages. Compare names and lengths only.

Write `SIGNALR_SERVER_KEY` as a **literal value on both services**, never as
a `${{service.VAR}}` reference and never as a shared variable. A dangling
reference renders silently as the empty string (seen on dev, 2026-09-26).
On realtime in enforced mode that now refuses to boot, which fails closed but
blocks every later realtime deploy until the value is fixed. On web it drops
`notify.ts` back to the legacy key, or to no key at all after step 5. After
every write, confirm the value's **length** on both services with
`list-variables` (48), not only that the name is present.
Rotation: never delete and re-add; overwrite in place. Order: realtime
switch `true` (transition), then overwrite realtime's key, then web's, wait
for `H4_SERVER_KEY_NOTIFY_OK` on the new realtime process, then switch
`false`. Between the two key writes web's old key is refused and web retries
with the legacy key, which transition accepts. That retry only exists while
web still has `SIGNALR_API_KEY`; after step 5, re-add it first or accept
dropped live events for that window.

Do these steps once per environment, in order. Do not start a step until
the previous step's proof line has appeared.

| # | Service | Action | Proof | Rollback |
|:---|:---|:---|:---|:---|
| −1 | realtime + web | **Pre-flight, read only.** `list-variables` on realtime: `SIGNALR_API_KEY` present and non-empty; `SIGNALR_SERVER_KEY` and `SIGNALR_NOTIFY_ACCEPT_PUBLIC_KEY` **absent**. On web: `PUBLIC_SIGNALR_KEY` and `SIGNALR_API_KEY` present with equal length; `SIGNALR_SERVER_KEY` absent. Record realtime's ACTIVE deployment id and commit. | All names and lengths as expected. If a stray `SIGNALR_SERVER_KEY` / `SIGNALR_NOTIFY_ACCEPT_PUBLIC_KEY` exists, or `SIGNALR_API_KEY` is empty, step 0 will refuse to boot. Resolve that first. | n/a (no change) |
| 0 | realtime | Deploy the H-4 code (prod: merge to realtime `main`; dev and research-platform: merge to realtime `dev`, taking the hotfix side of the add/add conflict in `Tests/ApiKeyAuthHandlerTests.cs`; `dev`'s copy is identical to `main`'s, so the hotfix side is a superset). No variable change. | Realtime log `H4_NOTIFY_AUTH_MODE=legacy`. `list-deployments` shows the ACTIVE deployment on the **new** commit, not the step −1 id. Then `H4_LEGACY_NOTIFY_KEY` warnings on chat activity, and DMs still arrive live. | Redeploy the step −1 deployment. Nothing else changed. |
| 1 | web | Deploy the rewrite `notify.ts` change to that env's web branch. No variable change. The change is one self-contained commit (`src/lib/server/realtime/notify.ts`, its `AGENTS.md`, `tests/unit/lib/server/realtime/notify.test.ts`; the rewrite has no `.env.example`), authored on `feature/research-platform`. **research-platform:** it is already on that branch. **dev:** cherry-pick that commit onto rewrite `dev`. **prod:** cherry-pick it onto the rewrite hotfix branch (`hotfix/prod-2026-09-26`) and ship it through the hotfix PR to `main`, not through a `dev → main` release. The cherry-pick applies cleanly: on 2026-09-26, `notify.ts` was the identical blob `3d5b0e0` on `origin/main`, `origin/dev`, `origin/hotfix/prod-2026-09-26` and `feature/research-platform`, and the other two files are new. If `git ls-tree <branch> -- src/lib/server/realtime/notify.ts` shows a different blob, re-check before picking. | Web deploy SUCCESS on the expected commit. Behaviour unchanged, still the legacy key. | Redeploy the previous web deployment. |
| 2 | realtime | Write `SIGNALR_NOTIFY_ACCEPT_PUBLIC_KEY=true` **and** `SIGNALR_SERVER_KEY=<new key>`, in one write if possible. If writes are one at a time, write the switch **first**: the switch alone stays in `legacy`, and the key alone refuses to boot. | `H4_NOTIFY_AUTH_MODE=transition`. `H4_LEGACY_NOTIFY_KEY` warnings continue. DMs still live. | If step 5 is done, **re-add web `SIGNALR_API_KEY` first**. Then, with the switch at `true` (do step 4's rollback first if needed; with `false` the delete refuses to boot), delete realtime `SIGNALR_SERVER_KEY` (back to `legacy`). If the deployment refused to boot, the old one is still serving: fix the value (≥32 chars, ≠ public key, switch set) and rewrite it. |
| 3 | web | Variable write: `SIGNALR_SERVER_KEY=<same key as step 2>`. | On the next chat or SAM event, realtime logs `H4_SERVER_KEY_NOTIFY_OK`, and `H4_LEGACY_NOTIFY_KEY` stops. No `SIGNALR_SERVER_KEY refused (401)` in web logs. Generate traffic yourself (send a DM between two QA accounts). Quiet logs alone prove nothing. | If step 5 is done, **re-add web `SIGNALR_API_KEY` first**, or web has no notify key at all and silently stops notifying. Then delete `SIGNALR_SERVER_KEY` on web (falls back to the legacy key, still accepted in transition). |
| 4 | realtime | **Close:** set `SIGNALR_NOTIFY_ACCEPT_PUBLIC_KEY=false` explicitly. Do not delete it: that refuses to boot. Only after step 3's proof, and after at least one full business day with zero `H4_LEGACY_NOTIFY_KEY`. | `H4_NOTIFY_AUTH_MODE=enforced`. A DM still arrives live. `curl -X POST <realtime>/api/notify -H "X-Api-Key: <PUBLIC_SIGNALR_KEY>" -H "Content-Type: application/json" -d '{"eventType":"ConversationUpdated","group":"h4-probe","payload":{}}'` returns **401** and logs `credential public-key`. Record **H-4a** shipped for this environment. H-4 stays OPEN until §H-4b ships. | Set `SIGNALR_NOTIFY_ACCEPT_PUBLIC_KEY=true` (back to transition). Safe even after step 5, because web sends the server key, which transition accepts. |
| 5 | web | Optional cleanup: delete `SIGNALR_API_KEY` from **web** only. It is no longer needed for notify. Keep web `PUBLIC_SIGNALR_KEY` and realtime `SIGNALR_API_KEY`: those are the public hub key. | Web redeploys; a DM still arrives live; no `SignalR notify failed: 401` in web logs. | Re-add web `SIGNALR_API_KEY` with the public key value. |

After step 5 the web service has exactly one notify key. Any later rollback
that makes realtime stop recognizing the server key (step 2 rollback,
realtime code rollback to pre-H-4) needs web `SIGNALR_API_KEY` restored
**first**.

Per environment:
- **dev**: realtime `dev` branch, web rewrite `dev`. Do this first. Watch
  `dev-env-sends-real-emails`: DM testing here touches a prod-cloned DB, so
  use QA accounts only.
- **research-platform**: realtime `dev` branch, web
  `feature/research-platform`. `SIGNALR_SERVICE_URL` is the public realtime
  domain, so notify crosses the public internet. Step 4 matters most here.
  Dev and research-platform share the realtime `dev` branch, so step 0 lands
  in both at once. Steps −1 and 0 proofs must be checked in **both**.
- **prod**: realtime `main`, web rewrite `main`. Do this last. Step 1 needs
  the `notify.ts` commit on rewrite `main`, via the hotfix branch and PR
  (see step 1). Until that ships, step 3 has no effect: old web code keeps
  sending the legacy key, warnings continue, and step 4 stays blocked. That
  is safe.

**New environments** skip the transition entirely: provision literal
`SIGNALR_SERVER_KEY` (web and realtime, ≥32 chars, different from the public
key) and realtime `SIGNALR_NOTIFY_ACCEPT_PUBLIC_KEY=false` before the first
deploy, so they boot straight into `enforced`. As of 2026-09-26
`infra/railway/environment-template.md` (group G10) and
`conductor/runbooks/second-deployment-railway.md` still prescribe the single
shared key, so an environment built from them lands in `legacy`. Updating
them is a coordinator follow-up, outside this change.

Never roll realtime code back to pre-H-4 while web sends the server key and
has no legacy `SIGNALR_API_KEY`: old realtime code knows only the public
key. Restore web `SIGNALR_API_KEY` first.

## §H-4b hub identity (OPEN, blocking H-4 closure)

**Hole.** `ApiKeyAuthHandler` copies the query `?userId=` into the `userId`
claim, and the only check is that the user exists (`OnConnectedAsync`).
Anyone holding the public key, which is everyone, can connect with
`?userId=<victim>` and, even in `enforced` mode:
1. push forged `UserPresenceChanged {userId: victim}` to every DM partner
   of the victim (on connect and disconnect);
2. `JoinConversation("<victim>-<partner>")`, then `SendTypingIndicator` /
   `MarkAsRead`, delivering forged typing and read receipts to the partner
   (`IsParticipant` compares against the attacker-chosen id);
3. receive the victim's `user:<victim>` group traffic: live
   `MessageReceived` / `MessageDeleted` DM payloads and SAM thinking events;
4. `GetConversationPresence` as the victim.

**Fix design (a separate change; it needs a root-layout load edit outside
this hotfix's files):**
- Add a new web and realtime secret, `SIGNALR_HUB_TOKEN_SECRET` (≥32 chars,
  distinct from both keys, server-only on web).
- In the root `+layout.server.ts` load, web mints
  `v1.<userId>.<expUnix>.<base64url(HMAC-SHA256(secret, "v1.<userId>.<expUnix>"))>`
  with a short expiry (for example 15 min), for signed-in users only.
- `signalr.svelte.ts` passes the token via `accessTokenFactory`, fetched
  fresh on each (re)connect, since the factory is re-invoked on reconnect.
  It drops `?userId=`.
- `ApiKeyAuthHandler` verifies the HMAC in constant time and checks expiry,
  then takes the `userId` claim from the token only. `GetUserId` already
  reads only the claim, so the query fallback is gone as of this change.
- Roll out with the same shape as H-4a: an explicit switch
  `SIGNALR_HUB_IDENTITY=query|token-or-query|token`. `token-or-query` logs
  `H4B_UNSIGNED_HUB_IDENTITY` per connection. End state `token` refuses the
  public key on the hub entirely, so `PUBLIC_SIGNALR_KEY` becomes
  removable.

## Other open items (not fixed by H-4a)

- **CORS** is `SetIsOriginAllowed(_ => true)` with credentials, and
  `ALLOWED_ORIGINS` is parsed but never used. Auth is bearer-style, not
  cookies, so this grants no ambient authority. After the split it no longer
  matters for notify, because the server key never reaches a browser. Once
  H-4b lands, an origin allow-list still does not protect a bearer token.
  Wiring `ALLOWED_ORIGINS` in is hygiene, and only safe once every
  environment's value is verified.
- `/api/health` returns `ex.Message` on failure (minor information leak).
