# ADR-0003: NetBox API-token pass-through

**Status:** Proposed
**Date:** 2026-10-06
**Amends:** ADR-0001 §7 (MCP writes use an explicit write mode)

## Context

Every serve mode nbox has today reaches NetBox with **one** credential: the
active profile's token. The modes differ only in who they let *talk to nbox*:

- **Pattern 2** (shared HTTP, OIDC) verifies the caller via an IdP JWT and maps
  the `sub` through `[serve.vault]` to that user's NetBox token — real per-user
  identity, at the cost of running an OIDC IdP and maintaining a vault table.
- **Pattern 3** (OIDC, read-only) verifies the caller but still queries NetBox
  as the service account. `docs/MCP.md` calls this what it is:
  *accountability, not per-user RBAC*.
- Static bearer and local stdio are single-credential by construction.

So a shared nbox server cannot reflect NetBox's own permissions per user: two
callers with different NetBox roles see the same (service-account-filtered)
data. The only per-user escape hatch today is Pattern 2's vault, which
presupposes an IdP — disproportionate when NetBox already issues per-user API
tokens and already enforces object permissions, constraints, and change
logging on them.

ADR-0001 §7 says MCP writes run "in one of two explicit modes" (OIDC+vault, or
local stdio). A third deployment shape needs a decision of the same rank,
because it changes what credential reaches NetBox.

## Decision

Add an opt-in multi-user mode, **NetBox API-token pass-through** (Pattern 4 in
the code, continuing the DESIGN §24 numbering), enabled by
`--netbox-token-passthrough` or `[serve].netbox_token_passthrough`:

1. **The caller's NetBox token is the credential.** Each request carries the
   caller's own NetBox API token in `X-NetBox-Token`, or in `Authorization`
   when that header is not already used by OIDC or `--http-token` (a host that
   can only set a bearer works; a JWT is never mistaken for a NetBox token).
   nbox forwards it verbatim; NetBox's object permissions, constraints, and
   change log apply to the real caller. No IdP, no vault.
2. **Fail closed.** A request without a caller token is rejected with `401`
   and a body naming the expected header. There is no fallback to the profile
   token — a misconfigured client gets an error, not someone else's rights.
3. **Per-token isolation is a correctness requirement, not an optimization.**
   NetBox filters read results by permission, so the same query returns
   different rows to different users: the read cache is partitioned per
   token fingerprint (first 8 bytes of SHA-256, hex), and `nbox_cache_clear`
   drops only the caller's own partition (no cross-tenant cache flush).
4. **Writes run under the caller's token, opt-in as before.** With
   `--allow-writes`, the plan/apply two-step and audit of ADR-0001 run
   unchanged, but the `PATCH`/`POST` to NetBox carries the caller's token
   (`WriteMode::Passthrough`); the plan store binds plans to
   `netbox-token:<fingerprint>`. A configured `[serve.vault]` is ignored in
   this mode, with a startup warning.
5. **HTTP transport only.** stdio has no per-request headers; requesting
   pass-through there is a usage error (exit 2), not a silent no-op.
6. **A routable bind is allowed**, because a shared server is the point —
   with the same condition as OIDC mode: terminate TLS in front. Callers send
   a real NetBox credential on every request; plaintext off-host would leak
   it.
7. **Attribution without exposure.** The token never appears in logs or
   errors (hand-written `Debug` renders `<redacted>`); the audit log records
   `auth=netbox-token` plus the fingerprint, which also keys the post-auth
   rate-limit bucket, so changing IP does not dodge the limit.

Implementation follows the existing `RequestContext::extensions` handoff that
`write_caller_from_extensions()` already uses for the OIDC `Identity`: the HTTP
gate extracts the token and stores it in the request `Parts`; each tool call
builds its `RequestScope` from the extensions. Task-locals do not work here —
the session manager runs its own worker task and the service factory has no
request handle.

## Consequences

Positive:

- A shared nbox deployment gets real per-user NetBox RBAC — reads, writes,
  and the NetBox change log — with zero identity infrastructure beyond the
  tokens NetBox already issues.
- The mode is opt-in and additive: every existing mode (Patterns 2 and 3,
  static bearer, stdio) is byte-for-byte unchanged when the flag is absent.
- NetBox stays the single authorization authority; nbox adds no own ACL layer
  that could drift from NetBox's.

Negative / trade-offs (accepted):

- **Plaintext tokens per request require TLS.** The mode is only as safe as
  the transport in front of it; the loopback-publish default and the "put a
  TLS-terminating proxy in front" documentation carry this.
- **The pre-auth rate-limit bucket stays keyed on the peer IP** — behind a
  reverse proxy, unauthenticated floods share one bucket. This is existing
  behavior shared with OIDC mode; fixing it needs a transport-level limit
  (or proxy-side), not an nbox-side one, and is documented rather than
  silently inherited.
- **nbox sees every caller token in memory** for the duration of a request.
  Mitigations: never logged, never echoed, `Debug` redacted, per-fingerprint
  audit only. Residual risk equals any API gateway fronting NetBox.
- **Token lifecycle is NetBox's.** A revoked or expired token fails at
  request time; nbox has no way to pre-validate beyond forwarding, and does
  not try.
- The `Authorization`-fallback placement is a heuristic (bearer-shaped
  strings that are not OIDC/static-bearer are treated as NetBox tokens). With
  OIDC or `--http-token` active it is disabled entirely, so the ambiguity it
  resolves is bounded.

Neutral:

- Cache partitions per fingerprint mean one user evicting hot entries cannot
  poison another's view; the cache was already per-profile-partitioned, so
  the additional keying is a small step.
- "Pattern 4" continues the DESIGN §24 numbering; that document is not part
  of the public repository, so the label is descriptive, not contractual.

## References

- ADR-0001 §7 — the two-mode MCP write decision this extends.
- ADR-0002 — the per-user-vault and local-stdio write modes; pass-through is
  the third, vault-free multi-user mode.
- `docs/MCP.md` — the pass-through security model and the pre-auth rate-limit
  note.
- [NetBox REST API authentication](https://netboxlabs.com/docs/netbox/integrations/rest-api/)
  — per-user API tokens and object-level permissions.
