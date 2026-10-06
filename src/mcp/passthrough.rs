//! NetBox API-token pass-through — the multi-user HTTP transport (Pattern 4).
//!
//! The other HTTP modes share **one** NetBox credential: the profile's service
//! token. Every caller therefore reads (and, with the vault, writes) as that one
//! account, and nbox's own audit log is the only per-user record. Pass-through
//! inverts that: each caller presents **their own** NetBox API token on every
//! `/mcp` request, nbox never holds a shared credential for them, and the last
//! hop to NetBox happens under the caller's identity. NetBox's own object
//! permissions become the authorization boundary, and NetBox's change log names
//! the human.
//!
//! Where the token may ride, in precedence order:
//!
//! 1. `X-NetBox-Token: <token>` — always accepted, and the **only** place the
//!    NetBox token may ride when `Authorization` is already claimed by another
//!    factor (an OIDC JWT, or the static `--http-token` bearer).
//! 2. `Authorization: Token <token>` — NetBox's own scheme.
//! 3. `Authorization: Bearer <token>` — what most MCP clients can set.
//!
//! (2) and (3) are only consulted when `Authorization` is *not* claimed; see
//! [`Placement`].
//!
//! The raw token never leaves this module in printable form: [`PassthroughToken`]
//! has a hand-written `Debug` that renders `<redacted>`, and every log/audit/
//! rate-limit/cache-partition use goes through the non-reversible
//! [`fingerprint`](PassthroughToken::fingerprint) instead.

use std::fmt;
use std::sync::Arc;

use axum::http::{HeaderMap, header};

/// The dedicated pass-through header. Lowercase — `HeaderMap` lookups are
/// case-insensitive, but the constant is also rendered in the
/// `WWW-Authenticate` hint, so keep it readable.
pub const NETBOX_TOKEN_HEADER: &str = "x-netbox-token";

/// Whether the `Authorization` header is available to carry the NetBox token.
///
/// In a plain pass-through deployment nothing else uses `Authorization`, so a
/// client can simply set a bearer and be done ([`Placement::Authorization`]).
/// When the operator layers pass-through on top of OIDC or the static bearer,
/// `Authorization` already carries *that* credential and the NetBox token must
/// use the dedicated header ([`Placement::DedicatedHeaderOnly`]) — otherwise a
/// JWT would be forwarded to NetBox as if it were an API token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// `X-NetBox-Token`, or `Authorization: Token|Bearer …`.
    Authorization,
    /// `X-NetBox-Token` only — `Authorization` belongs to another factor.
    DedicatedHeaderOnly,
}

impl Placement {
    /// Resolve the placement from the two things that can claim `Authorization`.
    pub fn resolve(oidc: bool, static_bearer: bool) -> Self {
        if oidc || static_bearer {
            Self::DedicatedHeaderOnly
        } else {
            Self::Authorization
        }
    }

    /// The caller-facing hint listing the accepted headers, used in the 401 body
    /// so a misconfigured client is told exactly where to put the token.
    pub fn hint(self) -> &'static str {
        match self {
            Self::Authorization => {
                "send your NetBox API token as `Authorization: Bearer <token>`, \
                 `Authorization: Token <token>`, or `X-NetBox-Token: <token>`"
            }
            Self::DedicatedHeaderOnly => {
                "send your NetBox API token as `X-NetBox-Token: <token>` \
                 (the Authorization header carries this server's own auth)"
            }
        }
    }
}

/// A caller-supplied NetBox API token, plus its stable non-reversible
/// fingerprint.
///
/// Cheap to clone (two `Arc<str>`), because it rides in axum request extensions
/// and is cloned into a per-request [`NetBoxClient`](crate::netbox::client::NetBoxClient).
#[derive(Clone)]
pub struct PassthroughToken {
    token: Arc<str>,
    fingerprint: Arc<str>,
}

impl fmt::Debug for PassthroughToken {
    /// Never prints the token — only the fingerprint, which is safe to log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PassthroughToken")
            .field("token", &"<redacted>")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

impl PassthroughToken {
    /// Normalize and wrap a raw header value. Returns `None` when nothing usable
    /// remains (empty, whitespace, or a bare scheme word).
    ///
    /// Normalization is [`crate::config::normalize_token`], the same one the CLI
    /// applies to `NBOX_TOKEN` — so a client that pastes NetBox's copied
    /// `Authorization` value into `X-NetBox-Token` still works.
    pub fn new(raw: &str) -> Option<Self> {
        let token = crate::config::normalize_token(raw)?;
        let fingerprint = fingerprint(&token);
        Some(Self {
            token: Arc::from(token.as_str()),
            fingerprint: Arc::from(fingerprint.as_str()),
        })
    }

    /// The raw token, for building the NetBox `Authorization` header. The only
    /// accessor that exposes the secret; call sites are the per-request client
    /// construction and nothing else.
    pub fn as_str(&self) -> &str {
        &self.token
    }

    /// A stable, non-reversible 16-hex-char label for this token.
    ///
    /// The same token always fingerprints to the same value, so it works as an
    /// audit caller key, a rate-limit bucket, and a cache partition — while
    /// being useless to an attacker who reads the log. (A SHA-256 prefix:
    /// truncation weakens only preimage resistance, which is irrelevant for an
    /// opaque label.)
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The audit / rate-limit caller key. Prefixed so it can never collide with
    /// a `sub:` / `client:` / `ip:` key from [`crate::mcp::audit::caller_key`].
    pub fn caller_key(&self) -> String {
        format!("netbox-token:{}", self.fingerprint)
    }
}

/// SHA-256 the token and render the first 8 bytes as hex. Mirrors
/// [`crate::mcp::audit::session_hash`]'s shape so log fields look consistent.
fn fingerprint(token: &str) -> String {
    use std::fmt::Write as _;

    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Pull the caller's NetBox token out of `headers` per `placement`.
///
/// `None` ⇒ no usable token was presented; the gate answers `401` (the request
/// never reaches NetBox). A present-but-blank header is treated as absent —
/// forwarding an empty token would make NetBox answer 403 with a confusing
/// message instead of nbox saying "you didn't send a token".
pub fn extract(headers: &HeaderMap, placement: Placement) -> Option<PassthroughToken> {
    if let Some(raw) = headers
        .get(NETBOX_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        && let Some(token) = PassthroughToken::new(raw)
    {
        return Some(token);
    }
    if placement == Placement::DedicatedHeaderOnly {
        return None;
    }
    // `normalize_token` strips a leading `Bearer`/`Token` scheme word, so both
    // Authorization spellings — and a bare value — resolve to the same token.
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(PassthroughToken::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn dedicated_header_wins_and_normalizes() {
        let map = headers(&[
            (NETBOX_TOKEN_HEADER, "  nbt_alice  "),
            ("authorization", "Bearer nbt_bob"),
        ]);
        let token = extract(&map, Placement::Authorization).expect("token");
        assert_eq!(token.as_str(), "nbt_alice");
    }

    #[test]
    fn authorization_accepts_both_schemes() {
        for value in ["Bearer nbt_alice", "Token nbt_alice", "nbt_alice"] {
            let map = headers(&[("authorization", value)]);
            let token = extract(&map, Placement::Authorization).expect("token");
            assert_eq!(token.as_str(), "nbt_alice", "for {value}");
        }
    }

    #[test]
    fn authorization_ignored_when_claimed() {
        let map = headers(&[("authorization", "Bearer some.jwt.value")]);
        assert!(
            extract(&map, Placement::DedicatedHeaderOnly).is_none(),
            "a JWT in Authorization must never be forwarded to NetBox as an API token"
        );
        // The dedicated header still works in the same mode.
        let map = headers(&[
            ("authorization", "Bearer some.jwt.value"),
            (NETBOX_TOKEN_HEADER, "nbt_alice"),
        ]);
        let token = extract(&map, Placement::DedicatedHeaderOnly).expect("token");
        assert_eq!(token.as_str(), "nbt_alice");
    }

    #[test]
    fn blank_header_falls_through_then_yields_none() {
        // A blank dedicated header must not shadow a usable Authorization value.
        let map = headers(&[
            (NETBOX_TOKEN_HEADER, "   "),
            ("authorization", "Bearer nbt_alice"),
        ]);
        assert_eq!(
            extract(&map, Placement::Authorization).map(|t| t.as_str().to_string()),
            Some("nbt_alice".to_string())
        );
        // Nothing usable anywhere ⇒ None (the gate turns this into a 401).
        let map = headers(&[(NETBOX_TOKEN_HEADER, "Bearer   ")]);
        assert!(extract(&map, Placement::Authorization).is_none());
        assert!(extract(&HeaderMap::new(), Placement::Authorization).is_none());
    }

    #[test]
    fn fingerprint_is_stable_distinct_and_not_the_token() {
        let alice = PassthroughToken::new("nbt_alice").unwrap();
        let alice2 = PassthroughToken::new("nbt_alice").unwrap();
        let bob = PassthroughToken::new("nbt_bob").unwrap();
        assert_eq!(alice.fingerprint(), alice2.fingerprint());
        assert_ne!(alice.fingerprint(), bob.fingerprint());
        assert_eq!(alice.fingerprint().len(), 16);
        assert!(!alice.fingerprint().contains("nbt_alice"));
        assert_eq!(
            alice.caller_key(),
            format!("netbox-token:{}", alice.fingerprint())
        );
    }

    #[test]
    fn debug_never_prints_the_token() {
        let token = PassthroughToken::new("nbt_supersecret").unwrap();
        let rendered = format!("{token:?}");
        assert!(!rendered.contains("nbt_supersecret"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn placement_resolution() {
        assert_eq!(Placement::resolve(false, false), Placement::Authorization);
        assert_eq!(
            Placement::resolve(true, false),
            Placement::DedicatedHeaderOnly
        );
        assert_eq!(
            Placement::resolve(false, true),
            Placement::DedicatedHeaderOnly
        );
    }
}
