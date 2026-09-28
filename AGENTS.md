# elevate-impact-realtime — agent notes

.NET 8 SignalR hub (`/hubs/elevate`) plus a server-to-server fan-out endpoint
(`POST /api/notify`). The rewrite (SvelteKit) is the only notify caller
(`elevate-impact-rewrite/src/lib/server/realtime/notify.ts`).

## §H-4 status: H-4a (notify key split) + H-14 (hub identity, formerly "H-4b")

H-4 closes **per environment only when BOTH H-4a and H-14 reach
`enforced` there.** Either one alone leaves a hole.

- **H-4a, the notify key split.** Once an environment reaches `enforced`,
  the public browser key can no longer call `/api/notify`. That closes
  arbitrary `MessageReceived`, `MessageDeleted`, `ConversationUpdated`,
  `SamThinking*` and `ReadReceiptReceived` injection through notify. It is
  safe to ship on its own. Runbook: §H-4a.
- **H-14, hub identity (tracked in `prod_hotfixes_20260926` as H-14; this
  file called it H-4b before).** Until H-14 is `enforced`, the hub trusts a
  self-asserted `?userId=`: anyone with the public key can connect as any
  existing user and receive their live DMs, even with H-4a `enforced`. The
  code for the fix is in this change (signed hub token). Runbook: §H-14.

**How to record it (prod_hotfixes_20260926):** mark H-4a shipped per
environment when §H-4a step 4's proof appears there, and H-14 shipped when
§H-14 step 5's proof appears. Record H-4 closed for an environment only when
both have. Reaching H-4a step 4 everywhere does **not** close H-4.

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
| Hub connect `/hubs/elevate` (Bearer / `access_token` / `X-Api-Key` / `?apiKey=`) | until H-14 `enforced`: yes, **as whatever `?userId=` the caller claims**; H-14 `enforced`: **no** (a verified hub token is required, §H-14) | **no** |
| Hub methods (`JoinConversation`, `LeaveConversation`, `SendTypingIndicator`, `MarkAsRead`, `GetConversationPresence`) | yes. The conversation-key checks compare against the **attacker-chosen** `userId`, so they check consistency only and are not an authorization boundary until H-14 is `enforced` (§H-14). | n/a |
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
| 4 | realtime | **Close:** set `SIGNALR_NOTIFY_ACCEPT_PUBLIC_KEY=false` explicitly. Do not delete it: that refuses to boot. Only after step 3's proof, and after at least one full business day with zero `H4_LEGACY_NOTIFY_KEY`. | `H4_NOTIFY_AUTH_MODE=enforced`. A DM still arrives live. `curl -X POST <realtime>/api/notify -H "X-Api-Key: <PUBLIC_SIGNALR_KEY>" -H "Content-Type: application/json" -d '{"eventType":"ConversationUpdated","group":"h4-probe","payload":{}}'` returns **401** and logs `credential public-key`. Record **H-4a** shipped for this environment. H-4 stays OPEN until §H-14 step 5 is also done here. | Set `SIGNALR_NOTIFY_ACCEPT_PUBLIC_KEY=true` (back to transition). Safe even after step 5, because web sends the server key, which transition accepts. |
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

## §H-14 hub identity (signed hub token)

### The hole

Before H-14, `ApiKeyAuthHandler` copied the query `?userId=` into the
`userId` claim, and the only check was that the user exists. Anyone holding
the public key (which ships in every browser bundle) could connect with
`?userId=<victim>` and:
1. receive the victim's `user:<victim>` group traffic, including the live
   `MessageReceived` DM payload (the rewrite pushes the full chat row, text
   included, from `chat.ts`) and SAM thinking events;
2. `JoinConversation("<victim>-<partner>")`, then `SendTypingIndicator` /
   `MarkAsRead`, delivering forged typing and read receipts (`IsParticipant`
   compared against the attacker-chosen id);
3. push forged `UserPresenceChanged {userId: victim}` to the victim's DM
   partners, and call `GetConversationPresence` as the victim.

H-4a `enforced` does not help with any of this: it gates `/api/notify`, not
the hub.

### Token (`Auth/HubTokens.cs`; minter `elevate-impact-rewrite/src/lib/server/realtime/hubToken.ts`)

```
base64url(payload) "." base64url(HMAC-SHA256(SIGNALR_HUB_TOKEN_KEY, base64url(payload)))
payload = {"sub":"<userId>","aud":"realtime-hub","iat":<unix s>,"exp":<unix s>}   (this key order, no whitespace)
```

- No header and no algorithm field, so there is nothing to negotiate or
  downgrade. The HMAC covers the payload segment exactly as transmitted, and
  it is checked with `CryptographicOperations.FixedTimeEquals` before any
  JSON is parsed.
- The verifier enforces all of these itself, not only the minter:
  `aud == "realtime-hub"`; exactly the four fields (no duplicates, no
  extras); `0 < exp - iat <= 900`; `iat <= now + 60`; `now <= exp + 60`
  (60 s clock skew); a strict base64url alphabet with no padding and a
  canonical encoding.
- Web mints 300 s tokens (`HUB_TOKEN_LIFETIME_SECONDS`) for
  `locals.user.id` only, at `POST /api/realtime/token`. That endpoint
  returns 401 without a session, 403 for API-key callers, and
  `Cache-Control: no-store` on every response.
- Shared vector: `Tests/HubIdentityTests.cs` and the rewrite's
  `tests/unit/lib/server/realtime/hubToken.test.ts` pin the same key,
  payload and token string. If either side changes the format, both tests
  fail.
- The key must be unique among **all** HMAC secrets in the system, not
  only the SignalR keys. Realtime refuses the public and server keys at
  boot; web (`resolveHubTokenKey`) also refuses `IDENTITY_SIGNING_KEY`,
  `AUDIT_LOG_SECRET` and `EMAIL_LOG_HASH_SECRET`. `IDENTITY_SIGNING_KEY`
  signs a structurally similar `payload.sig` token (`sam/identityToken.ts`).
  Its hex signature cannot pass the strict base64url decode here today, but
  one shared key must never be the only thing keeping two token types
  apart.

### Connection lifetime (`Hubs/HubEndpoint.cs`)

SignalR authenticates a connection once, at connect time. Without more, a
token would only limit when a connection can be **opened**: whoever holds a
valid token (the victim's leaked one, or a logged-out session's last one)
could keep the socket and its `user:<victim>` traffic indefinitely. So:
- On the token path, `ApiKeyAuthHandler` sets the ticket's
  `AuthenticationProperties.ExpiresUtc` to the token's `exp`, and the hub is
  mapped with `CloseOnAuthenticationExpiration = true`. Realtime closes the
  connection at `exp`, roughly 5 minutes after mint.
- The browser's `withAutomaticReconnect` then reconnects, and
  `accessTokenFactory` mints a fresh token for the **current** session. A
  logged-out session gets 401 from the token endpoint, so its socket dies
  at the next expiry and does not come back.
- The asserted path (public key + `?userId=`) sets no expiry, so `legacy`
  and `transition` connections behave exactly as before H-14.
- Cost: one reconnect per tab per ~5 minutes (a token fetch, a negotiate,
  and the `OnConnectedAsync` user and partner queries). The presence grace
  period (5 s) absorbs it, so partners see no offline flap. The browser
  re-joins its conversation groups and delays the "reconnecting" badge
  (`elevate-impact-rewrite/src/lib/realtime/AGENTS.md` §hub-token).

`HubConnectionLifetimeTests` proves this over a real WebSocket (TestServer
and the .NET SignalR client, credential in `?access_token=` like the
browser): the token connection closes at `exp` and reconnects on a fresh
token; a connection that cannot mint a fresh token (logout) ends in
`Closed`; an asserted connection stays up.

### Logging (`Auth/CredentialLogSafety.cs`)

On WebSocket and SSE the browser sends the token as `?access_token=`.
ASP.NET Core Hosting logs every request's URL at Information ("Request
starting … ?id=…&access_token=…"), so with the old Serilog config
(`MinimumLevel.Information()`, no overrides) every minted token landed in
Railway's realtime logs. `CredentialLogSafety.Configure`, shared by
`Program.cs` and the tests:
- raises `Microsoft.AspNetCore` to Warning, which drops the per-request
  lines;
- enriches every event: any string property containing `access_token=` or
  `apiKey=` has the value replaced with `[redacted]`, whatever its level or
  category.
`HubToken_NeverReachesTheLogs_ButWouldWithoutCredentialLogSafety` runs a
real connection under both configs: the old one logs the token, the new one
does not. Residual exposure: Railway's own HTTP edge logs record the request
path, and may record the query. Check that in each environment. The
connection-lifetime bound above limits what a token from any log can do to
about 6 minutes (300 s lifetime + 60 s skew, and the connection closes at
`exp`).

### Wire format and deploy-order safety

The browser (`src/lib/realtime/signalr.svelte.ts` + `hubCredential.ts`):
- **always** keeps `?userId=<id>` on the hub URL, which pre-H-14 realtime
  needs;
- puts exactly **one** credential in the SignalR credential slot (Bearer on
  negotiate, `access_token` on WebSocket/SSE): a freshly minted hub token when
  the endpoint returns one, else the public key (`{"token":null}` means web
  has no `SIGNALR_HUB_TOKEN_KEY`; a 404 means web was rolled back under a
  newer tab);
- if the initial `start()` fails with a **401** after sending a token, logs
  `H14_HUB_TOKEN_REFUSED` to the browser console and retries **once** with
  the public key, pinned for that connection's lifetime. Any other failure
  (network, 5xx, timeout) does not pin the public key, so a transient error
  cannot leave a tab on the legacy wire.

Realtime reads the same slot (`Bearer ?? X-Api-Key ?? access_token ??
apiKey`). If the value is the public key, it takes the asserted path
(legacy and transition only). Otherwise, if a token key is configured, it
verifies the value as a token and takes identity **only** from `sub`, and
`?userId=` is ignored. There is no fallback from a failed token to
`?userId=`.

Why the token cannot ride in its own query parameter: the SignalR JS client
fixes the URL per `HubConnection`, so only `accessTokenFactory` can supply a
fresh credential on each automatic reconnect. And pre-H-14 realtime reads
`access_token` before `apiKey`, so the slot must hold the public key for old
code. Hence one slot, with a client-side retry.

| Realtime | Web has no hub key | Web has the hub key |
|:---|:---|:---|
| pre-H-14 code | public key + `?userId=` (today) | token refused → retry with public key → **live** |
| H-14 `legacy` | public key + `?userId=` | token refused (cannot verify) → retry → **live** |
| H-14 `transition` | public key, `H14_LEGACY_HUB_IDENTITY` | **token** (`H14_HUB_TOKEN_OK`) |
| H-14 `enforced` | **refused**: polling fallback only | **token** |

`WireMatrix_EveryDeployOrderKeepsAConnection` proves the realtime half of
this table. Every order of the realtime code, web code, realtime variables
and web variable keeps connections live. **The one required order: enforce
(step 5) only after web mints tokens (step 3 proof), and only while every
branch that can deploy web into that environment carries the H-14 web code
(step 5 precondition).** After step 5, any web deploy without
`/api/realtime/token` (a rollback, or a release from a branch that never got
the code) silently drops every tab to polling: the endpoint 404s, the
browser falls back to the public key, and enforced refuses it. The only
signal is a spike of `Hub connect refused (… credential public-key …)`
warnings in realtime. The boot guard cannot check any of this, because
realtime cannot see web's variables or code.

Two degradations to know about:
- The public-key retry runs only on the initial `start()`. A tab that
  connected with a token and then has to reconnect after realtime lost the
  key (a step 2 rollback, or realtime code rolled back) exhausts its
  reconnect schedule and drops to polling until reload. So roll back **web
  first** (delete web `SIGNALR_HUB_TOKEN_KEY`), then realtime.
- Tabs opened before step 1 run the old JS (public key only). In `enforced`
  they drop to polling on their next reconnect, until reloaded. This is
  another reason for step 4's soak.

### Modes (`HubIdentityKeys.Mode`, logged at boot as `H14_HUB_IDENTITY_MODE=<mode>`)

| `SIGNALR_HUB_TOKEN_KEY` | `SIGNALR_HUB_ACCEPT_ASSERTED_USERID` | Mode | Hub accepts |
|:---|:---|:---|:---|
| unset / blank | unset / blank, or `true` / `1` | `legacy` | public key + `?userId=` (today); tokens refused |
| unset / blank | `false` / `0` | **boot refused** | the previous deployment keeps serving |
| set | `true` / `1` | `transition` | verified token, or public key + `?userId=` (warns per connection) |
| set | `false` / `0` | `enforced` | verified token **only**; `?userId=` ignored; public key alone refused |
| set | unset / blank | **boot refused** | the previous deployment keeps serving |

Boot refusals, which mirror §H-4a's reasoning in both directions:
- `SIGNALR_HUB_TOKEN_KEY` shorter than 32 characters after trimming.
- `SIGNALR_HUB_TOKEN_KEY` equal to `SIGNALR_API_KEY` (the public key) or to
  `SIGNALR_SERVER_KEY`.
- `SIGNALR_HUB_TOKEN_KEY` set while the switch is unset or blank.
- The switch is `false` while `SIGNALR_HUB_TOKEN_KEY` is unset or blank.
- The switch is not one of `true/false/1/0`.
- `SIGNALR_HUB_TOKEN_KEY_PREVIOUS` (rotation only) set without
  `SIGNALR_HUB_TOKEN_KEY`, shorter than 32 characters, equal to the current
  key, or equal to the public or server key.

H-14 and H-4a are independent switches. Either can be in any mode. In
`enforced`, every identity the hub uses comes from the verified `sub`:
`GetUserId`, the `user:{id}` group join, `JoinConversation` /
`IsParticipant`, typing, read receipts, presence, and
`GetConversationPresence`.

### Log lines to grep

| Token | Where | Level | Meaning |
|:---|:---|:---|:---|
| `H14_HUB_IDENTITY_MODE=legacy\|transition\|enforced` | realtime, boot | Warning until `enforced`, then Info | the running mode |
| `H14_LEGACY_HUB_IDENTITY` | realtime, once per hub connection | Warning | a connection identified by self-asserted `?userId=`; do not close while these continue |
| `H14_HUB_TOKEN_OK` | realtime, once per process | Info | proof that web is minting tokens this process verifies with the **current** key |
| `H14_HUB_TOKEN_ROTATION` | realtime, boot | Warning | `SIGNALR_HUB_TOKEN_KEY_PREVIOUS` is set; a rotation is in progress |
| `H14_HUB_TOKEN_PREVIOUS_KEY` | realtime, once per hub connection | Warning | a connection verified by the previous key; delete `SIGNALR_HUB_TOKEN_KEY_PREVIOUS` only once these stop |
| `Hub connect refused (mode …, credential public-key\|invalid-token\|unknown, reason …)` | realtime, per refused request | Warning | a refused connect. `invalid-token` with reason `bad-signature` right after a key write means a web/realtime key mismatch. |
| `H14_HUB_TOKEN_REFUSED` | browser console | warn | the client fell back to the public key |
| `[realtime] hub token disabled: …` | web | error | web's `SIGNALR_HUB_TOKEN_KEY` is short or equals another key. Web mints nothing (legacy). |

### Rollout runbook (zero outage, once per environment, in order)

Keys: generate one **per environment**, never shared, with
`node -e "console.log(require('crypto').randomBytes(36).toString('base64url'))"`
(48 chars). It must differ from `SIGNALR_API_KEY` / `PUBLIC_SIGNALR_KEY`
and from `SIGNALR_SERVER_KEY`. Write it as a **literal on both services**,
never as a `${{…}}` reference or a shared variable (the same dangling
reference hazard as §H-4a). After each write, confirm the **length** (48)
with `list-variables`, and never paste the value anywhere. On web it is a
private variable: **never** name it `PUBLIC_…`. Every variable write
redeploys the target service's branch head, so check the live commit equals
the branch head before writing.

| # | Service | Action | Proof | Rollback |
|:---|:---|:---|:---|:---|
| −1 | realtime + web | **Pre-flight, read only.** Realtime: `SIGNALR_HUB_TOKEN_KEY` and `SIGNALR_HUB_ACCEPT_ASSERTED_USERID` **absent**. Web: `SIGNALR_HUB_TOKEN_KEY` absent. Record both ACTIVE deployment ids and commits. | Names as expected. A stray switch `false` without a key refuses to boot at step 0. | n/a |
| 0 | realtime | Deploy the H-14 code. No variable change. Order-independent with step 1. | `H14_HUB_IDENTITY_MODE=legacy`; ACTIVE deployment on the new commit; `H14_LEGACY_HUB_IDENTITY` on connections; DMs still live. | Redeploy the step −1 deployment. |
| 1 | web | Deploy the H-14 rewrite code (see *Rewrite cherry-pick* below). No variable change. | Deploy SUCCESS on the expected commit. From a logged-in browser, `fetch('/api/realtime/token',{method:'POST'})` returns `{"token":null}` with `cache-control: no-store`; logged out, it returns 401. DMs still live. | **If step 5 is done, do step 5's rollback (switch `true`) first**, or every tab drops to polling (the old web code has no endpoint and sends only the public key). Then redeploy the previous web deployment. |
| 2 | realtime | Write `SIGNALR_HUB_ACCEPT_ASSERTED_USERID=true` **and** `SIGNALR_HUB_TOKEN_KEY=<new key>`, in one write if possible. If writes are one at a time, write the switch **first** (the switch alone stays `legacy`; the key alone refuses to boot). | `H14_HUB_IDENTITY_MODE=transition`; `H14_LEGACY_HUB_IDENTITY` continues; DMs live. | With the switch at `true`, delete realtime `SIGNALR_HUB_TOKEN_KEY` (back to `legacy`). If step 3 is done, do step 3's rollback **first**. |
| 3 | web | Write `SIGNALR_HUB_TOKEN_KEY=<same key as step 2>`. | Open `/messages` in a **fresh** tab as a QA account. Realtime logs `H14_HUB_TOKEN_OK`; that connection logs **no** `H14_LEGACY_HUB_IDENTITY`; the browser console shows no `H14_HUB_TOKEN_REFUSED`; a DM between two QA accounts arrives live. Generate the traffic yourself: quiet logs prove nothing. The realtime log has **no** `access_token=` value for that connect (`CredentialLogSafety`). | **If step 5 is done, do step 5's rollback (switch `true`) first.** Then delete web `SIGNALR_HUB_TOKEN_KEY`. The endpoint returns `{"token":null}` and clients go back to the public key, which transition accepts. |
| 4 | — | **Soak, read only.** At least one full business day with zero `H14_LEGACY_HUB_IDENTITY` (stale pre-step-1 tabs are the usual tail) and no `invalid-token` refusals. | Log search is clean for the whole window. | n/a |
| 5 | realtime | **Precondition (read only):** every branch that deploys web into this environment contains the H-14 web files. Check each with `git ls-tree origin/<branch> -- src/lib/server/realtime/hubToken.ts src/routes/api/realtime/token/+server.ts src/lib/realtime/hubCredential.ts` in the rewrite (three paths printed, none missing). The branches are: dev → `dev`; research-platform → `feature/research-platform`; prod → `main` **and** `dev`, because the next `dev → main` release redeploys prod web from `dev`. For prod, also confirm the rewrite hotfix has reached `dev`: `git merge-base --is-ancestor <hotfix H-14 commit> origin/dev`, or the file check above on `origin/dev` if it arrived by cherry-pick. **Close:** set `SIGNALR_HUB_ACCEPT_ASSERTED_USERID=false` explicitly. Do not delete it: that refuses to boot. | `H14_HUB_IDENTITY_MODE=enforced`. A DM still arrives live in a fresh tab. `curl -i -X POST "<realtime>/hubs/elevate/negotiate?negotiateVersion=1&userId=<a QA user id>" -H "Authorization: Bearer <PUBLIC_SIGNALR_KEY>"` returns **401** and realtime logs `credential public-key, reason hub token required`. Record **H-14** shipped for this environment. H-4 closes here only if §H-4a step 4 is also done. | Set `SIGNALR_HUB_ACCEPT_ASSERTED_USERID=true` (back to transition). |

**Rollback triggers after step 5** (do step 5's rollback, switch `true`,
first, then investigate): a spike of `Hub connect refused (mode enforced,
credential public-key, …)` after **any** web deploy, including routine
releases unrelated to H-14 (the deploy lacked the H-14 web code); or a
spike of `credential invalid-token, reason bad-signature` after a key write
(key mismatch between the services).

**Rotation** (no transition mode, no degradation). Realtime verifies against
both keys while `SIGNALR_HUB_TOKEN_KEY_PREVIOUS` is set:
1. Realtime, one write: `SIGNALR_HUB_TOKEN_KEY_PREVIOUS=<current key>` and
   `SIGNALR_HUB_TOKEN_KEY=<new key>`. Proof: `H14_HUB_TOKEN_ROTATION` at
   boot, and `H14_HUB_TOKEN_PREVIOUS_KEY` on connections (web still mints
   with the old key; it still verifies). Rollback: restore the old key as
   `SIGNALR_HUB_TOKEN_KEY` and delete `…_PREVIOUS`.
2. Web: overwrite `SIGNALR_HUB_TOKEN_KEY=<new key>`. Proof: from a fresh
   tab, a connection with no `H14_HUB_TOKEN_PREVIOUS_KEY`. Rollback: put
   the old key back on web (realtime still accepts it).
3. Wait at least 6 minutes after web's redeploy (300 s lifetime + 60 s
   skew; every live connection has reconnected on a new-key token by then),
   until `H14_HUB_TOKEN_PREVIOUS_KEY` stops. Then delete realtime
   `SIGNALR_HUB_TOKEN_KEY_PREVIOUS`. Proof: no `H14_HUB_TOKEN_ROTATION` at
   boot.
The order matters: realtime first. Web on the new key before realtime knows
it produces `bad-signature` on every reconnect, and in `enforced` those tabs
drop to polling (the public-key retry runs only on the initial start and
only helps in `transition`). Never delete and re-add a key; overwrite it in
place.

**What `enforced` does and does not guarantee.** It guarantees that every
hub identity comes from a `sub` that web signed for a session user; that no
token opens a connection more than ~6 minutes after mint; and that no token
connection outlives its token's `exp`. It does **not** revoke on logout
faster than that, and it inherits the session model: the rewrite's session
cookie is a stateless 12 h token (`auth/handle.ts` consults the DB session
only once the token expires), so a captured cookie can keep minting hub
tokens after logout, for up to 12 h. Every API has the same exposure. The
fix, a session-revocation check, is a follow-up outside H-14.

Per environment:
- **dev** (do first): realtime `dev` branch; web rewrite `dev`. The web
  code reaches rewrite `dev` by cherry-picking the H-14 web commit (the
  one authored on `feature/research-platform`, see *Rewrite cherry-pick*)
  onto `dev`, exactly like H-4a step 1. QA accounts only: the dev DB is
  prod-cloned (`dev-env-sends-real-emails`).
- **research-platform**: realtime `dev` branch; web
  `feature/research-platform`, which already carries the rewrite change.
  Dev and research-platform share the realtime `dev` branch, so step 0 lands
  in both at once. Check the step −1 and step 0 proofs in **both**. The
  realtime domain is public, so step 5 matters most here.
- **prod** (last): realtime `main` via the hotfix PR; web rewrite `main` via
  the rewrite hotfix branch and its PR, not a `dev → main` release. Until
  the web change is on `main`, step 3 has no effect (old web code has no
  endpoint), so step 5 stays blocked. That is safe. Before prod step 5, the
  change must also be on rewrite `dev` (the dev cherry-pick above, or a
  merge of `main` back into `dev`). Otherwise the next `dev → main` release
  deploys prod web without the endpoint and takes prod realtime to
  polling-only (see step 5's precondition).

**New environments** skip the transition: provision the literal
`SIGNALR_HUB_TOKEN_KEY` on both services and
`SIGNALR_HUB_ACCEPT_ASSERTED_USERID=false` before the first deploy.
`infra/railway/environment-template.md` and
`conductor/runbooks/second-deployment-railway.md` do not mention it yet
(coordinator follow-up, outside this change).

**Rewrite cherry-pick.** The web half is `src/lib/server/realtime/hubToken.ts`,
`src/routes/api/realtime/token/+server.ts` (plus the colocated `server.test.ts`),
`src/lib/realtime/hubCredential.ts` (plus `hubCredential.test.ts`),
`src/lib/realtime/conversationGroups.ts`,
`src/lib/realtime/signalr.svelte.ts` (plus `signalr.test.ts`), both realtime
`AGENTS.md` files, and
`tests/unit/lib/server/realtime/hubToken.test.ts`. Pick H-4a's
`2f993b49` first: `src/lib/server/realtime/AGENTS.md` was created by it.
On 2026-09-26, `signalr.svelte.ts` and `src/lib/realtime/AGENTS.md` were
identical on `origin/main` and `feature/research-platform`, and the other
files are new, so the pick applies cleanly.

`PUBLIC_SIGNALR_KEY` / `SIGNALR_API_KEY` stay after step 5. Realtime still
requires `SIGNALR_API_KEY` at boot. In `enforced` the public key opens
nothing on its own. Removing it is a later cleanup that needs a
`RealtimeKeys` change.

## Other open items (not fixed by H-4a or H-14)

- **CORS** is `SetIsOriginAllowed(_ => true)` with credentials, and
  `ALLOWED_ORIGINS` is parsed but never used. Auth is bearer-style, not
  cookies, so this grants no ambient authority. After the split it no longer
  matters for notify, because the server key never reaches a browser. Once
  H-14 lands, an origin allow-list still does not protect a bearer token.
  Wiring `ALLOWED_ORIGINS` in is hygiene, and only safe once every
  environment's value is verified.
- `/api/health` returns `ex.Message` on failure (minor information leak).
