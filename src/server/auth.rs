//! Authentication of the MCP endpoints.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use super::AppState;
use crate::auth::{AuthError, TokenIdentity};
use crate::gateway::Caller;
use crate::oidc::{OidcError, Provider};
use crate::policy::OptOuts;
use crate::principal::{PrincipalPolicy, TokenScope};
use crate::store::{JwtSubject, PAT_PREFIX, Store, StoreError};

/// 401 with the `WWW-Authenticate` challenge.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
    )
        .into_response()
}

/// The address of the client, for the token's `last_used_ip`: the peer, or behind our
/// reverse proxy the address the proxy saw. `None` without connection info (tests that
/// call the router directly).
pub(super) struct ClientIp(pub Option<String>);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip());
        let forwarded = parts
            .headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join(",");
        Ok(Self(select_client_ip(peer, &forwarded)))
    }
}

/// Whether the address is loopback or private: a reverse proxy on this host or network,
/// whose `X-Forwarded-For` we believe.
fn is_trusted_proxy(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        // `fc00::/7`, unique local addresses
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.segments().first().is_some_and(|s| s & 0xfe00 == 0xfc00)
        }
    }
}

/// The client address: the rightmost parseable `X-Forwarded-For` entry (the one our own
/// proxy appended) when the peer is a loopback or private address, else the peer. Entries
/// further left are client-supplied and not trusted.
fn select_client_ip(peer: Option<IpAddr>, forwarded_for: &str) -> Option<String> {
    let peer = peer?;
    if is_trusted_proxy(peer)
        && let Some(forwarded) = forwarded_for
            .rsplit(',')
            .find_map(|entry| entry.trim().parse::<IpAddr>().ok())
    {
        return Some(forwarded.to_string());
    }
    Some(peer.to_string())
}

/// Resolve who is calling from the request headers (the error is boxed: a
/// `Response` is large for an error type). `client_ip` is recorded on a token's use.
///
/// A bearer token with the personal access token prefix (multi-user mode only)
/// becomes a [`Caller::Principal`]: its owner's policy, narrowed by the token
/// scope and the owner's opt-outs. So does a JWT access token of an OIDC provider that
/// accepts them (resource-server mode), as the user or bound service account it names,
/// with no narrowing. Anything else goes through the legacy
/// [`AuthManager`](crate::auth::AuthManager). Standalone, a named `[[tokens]]`
/// entry is a [`Caller::Token`], the shared token or no auth at all is
/// [`Caller::Open`]. In multi-user mode a `[[tokens]]` entry is a config service
/// account, a [`Caller::Principal`] with the groups that list it in
/// `service_accounts`, and the shared token is refused.
/// Multi-user mode is deny-by-default: with no legacy auth configured, a
/// request without a PAT is answered 401, never `Open`.
pub(super) async fn authenticate(
    headers: &HeaderMap,
    state: &AppState,
    client_ip: Option<&str>,
) -> Result<Caller, Box<Response>> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let provided_token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);

    if provided_token.starts_with(PAT_PREFIX) {
        return authenticate_pat(provided_token, state, client_ip).await;
    }

    if provided_token.starts_with(crate::store::OAUTH_ACCESS_PREFIX) {
        return super::oauth::authenticate_oauth_token(provided_token, state, client_ip).await;
    }

    // A JWT of no accepting provider is not ours: it may be a legacy token
    if let Some((_, oidc)) = state.multi_user()
        && looks_like_jwt(provided_token)
        && let Some(provider) = oidc.access_token_provider(provided_token)
    {
        return authenticate_jwt(provided_token, provider, state).await;
    }

    let auth_manager = state.auth_manager.load();
    if !auth_manager.auth_required() {
        return if state.multi_user().is_some() {
            crate::metrics::record_authn("pat", "invalid");
            Err(Box::new(unauthorized()))
        } else {
            crate::metrics::record_authn("open", "ok");
            Ok(Caller::Open)
        };
    }

    if provided_token.is_empty() {
        crate::metrics::record_authn("legacy_token", "invalid");
        return Err(Box::new(unauthorized()));
    }

    if let Some((store, _)) = state.multi_user() {
        // Multi-user mode counts in Postgres, so the replicas share one limit
        // The shared token has no identity to put under RBAC
        let Ok(Some(identity)) = auth_manager.identify(provided_token) else {
            crate::metrics::record_authn("service_token", "invalid");
            return Err(Box::new(unauthorized()));
        };
        let limit = auth_manager.effective_limit(identity.rate_limit_per_minute);
        within_rate_limit(
            store,
            "service_token",
            &format!("config:{}", identity.name),
            limit,
        )
        .await?;
        crate::metrics::record_authn("service_token", "ok");
        return Ok(config_account(&identity, state));
    }

    match auth_manager.validate_token(provided_token) {
        Ok(Some(identity)) => {
            crate::metrics::record_authn("legacy_token", "ok");
            Ok(Caller::Token(identity))
        }
        Ok(None) => {
            crate::metrics::record_authn("legacy_token", "ok");
            Ok(Caller::Open)
        }
        Err(AuthError::RateLimited { .. }) => {
            crate::metrics::record_authn("legacy_token", "rate_limited");
            crate::metrics::record_authz_denied("rate_limit");
            Err(Box::new(too_many_requests()))
        }
        Err(_) => {
            crate::metrics::record_authn("legacy_token", "invalid");
            Err(Box::new(unauthorized()))
        }
    }
}

fn too_many_requests() -> Response {
    StatusCode::TOO_MANY_REQUESTS.into_response()
}

/// Count a request in the shared Postgres window under `key`: 429 when the limit
/// (requests per minute, 0 = unlimited) is used up, counted as `method` in
/// `axon_authn_total`. A store error lets the request through: the limit protects
/// the backends, it is not an access check.
async fn within_rate_limit(
    store: &Store,
    method: &str,
    key: &str,
    limit: u32,
) -> Result<(), Box<Response>> {
    if limit == 0 {
        return Ok(());
    }
    match store.hit_rate_limit(key, limit).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            crate::metrics::record_authn(method, "rate_limited");
            crate::metrics::record_authz_denied("rate_limit");
            Err(Box::new(too_many_requests()))
        }
        Err(error) => {
            tracing::warn!(%error, key, "Rate limit check failed, letting the request through");
            Ok(())
        }
    }
}

/// A `[[tokens]]` entry in multi-user mode: a service account declared in config, under
/// the policy of the config groups that list it. Its `allowed_*` narrow it like a token
/// scope; it has no opt-outs.
fn config_account(identity: &TokenIdentity, state: &AppState) -> Caller {
    let policy = state.policy.current();
    let groups = policy.groups_for_config_account(&identity.name);
    Caller::Principal(
        PrincipalPolicy::new(
            format!("config:{}", identity.name),
            policy.effective(&groups),
            OptOuts::default(),
            TokenScope {
                backends: identity.allowed_backends.clone(),
                tools: identity.allowed_tools.clone(),
            },
        )
        .with_service_account(),
    )
}

/// A personal access token or a service account's token.
async fn authenticate_pat(
    token: &str,
    state: &AppState,
    client_ip: Option<&str>,
) -> Result<Caller, Box<Response>> {
    let Some((store, oidc)) = state.multi_user() else {
        return Err(Box::new(unauthorized()));
    };
    let principal = match store.authenticate_token(token, client_ip).await {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            crate::metrics::record_authn("pat", "invalid");
            return Err(Box::new(unauthorized()));
        }
        Err(error) => return Err(Box::new(unavailable(&error))),
    };
    let method = if principal.is_service_account {
        "service_token"
    } else {
        "pat"
    };
    within_rate_limit(
        store,
        method,
        &format!("pat:{}", principal.token.id),
        state.auth_manager.load().effective_limit(0),
    )
    .await?;

    crate::metrics::record_authn(method, "ok");

    let owner = &principal.owner;
    let policy = state.policy.current();
    let groups = if principal.is_service_account {
        policy.groups_for_service_account(owner.id, &owner.subject)
    } else {
        // No configured provider for the issuer: no IdP mapping applies
        let provider_id = oidc.id_for_issuer(&owner.issuer).unwrap_or("");
        policy.groups_for(owner.id, provider_id, &owner.groups)
    };
    let opt_outs = opt_outs(store, owner.id).await?;

    let owner_label = owner
        .email
        .clone()
        .or_else(|| owner.display_name.clone())
        .unwrap_or_else(|| owner.id.to_string());
    let mut caller = PrincipalPolicy::new(
        format!("{owner_label} / {}", principal.token.name),
        policy.effective(&groups),
        opt_outs,
        TokenScope {
            backends: principal.token.scope_backends,
            tools: principal.token.scope_tools,
        },
    )
    .with_identity(Some(owner.id), Some(principal.token.id));
    if principal.is_service_account {
        caller = caller.with_service_account();
    }
    if let Some(toolset) = principal.toolset {
        caller = caller.with_toolset(toolset);
    }
    Ok(Caller::Principal(caller))
}

/// Three non-empty base64url parts, which is all a JWT has to look like
fn looks_like_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
    let base64url = |part: Option<&str>| {
        part.is_some_and(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    };
    base64url(parts.next())
        && base64url(parts.next())
        && base64url(parts.next())
        && parts.next().is_none()
}

/// A JWT access token of `provider`, acting as the bound service account or as the user
/// with that issuer and subject. The token's groups replace the stored ones when it has
/// any. Not narrowed: the caller has the policy of the principal it acts as.
async fn authenticate_jwt(
    token: &str,
    provider: &Provider,
    state: &AppState,
) -> Result<Caller, Box<Response>> {
    let Some((store, _)) = state.multi_user() else {
        return Err(Box::new(unauthorized()));
    };
    let claims = match provider.verify_access_token(token).await {
        Ok(claims) => claims,
        Err(OidcError::Expired) => {
            crate::metrics::record_authn("jwt", "expired");
            return Err(Box::new(unauthorized()));
        }
        Err(error) => {
            tracing::info!(provider = provider.id(), %error, "A JWT access token was refused");
            crate::metrics::record_authn("jwt", "invalid");
            return Err(Box::new(unauthorized()));
        }
    };
    let subject = match store
        .resolve_jwt_subject(provider.issuer(), &claims.subject)
        .await
    {
        Ok(Some(subject)) => subject,
        Ok(None) => {
            crate::metrics::record_authn("jwt", "invalid");
            return Err(Box::new(unauthorized()));
        }
        Err(error) => return Err(Box::new(unavailable(&error))),
    };
    let (owner, is_service_account) = match subject {
        JwtSubject::ServiceAccount(owner) => (owner, true),
        JwtSubject::User(owner) => (owner, false),
    };
    within_rate_limit(
        store,
        "jwt",
        &format!("jwt:{}", owner.id),
        state.auth_manager.load().effective_limit(0),
    )
    .await?;

    crate::metrics::record_authn("jwt", "ok");

    let policy = state.policy.current();
    let groups = if is_service_account {
        policy.groups_for_service_account(owner.id, &owner.subject)
    } else {
        let claim_groups = claims.groups.as_ref().unwrap_or(&owner.groups);
        policy.groups_for(owner.id, provider.id(), claim_groups)
    };
    let opt_outs = opt_outs(store, owner.id).await?;

    let owner_label = owner
        .email
        .clone()
        .or_else(|| owner.display_name.clone())
        .unwrap_or_else(|| owner.id.to_string());
    let mut caller = PrincipalPolicy::new(
        format!("{owner_label} / jwt"),
        policy.effective(&groups),
        opt_outs,
        TokenScope::default(),
    )
    .with_identity(Some(owner.id), None);
    if is_service_account {
        caller = caller.with_service_account();
    }
    Ok(Caller::Principal(caller))
}

async fn opt_outs(store: &Store, user_id: Uuid) -> Result<OptOuts, Box<Response>> {
    store
        .opt_outs(user_id)
        .await
        .map(|rows| OptOuts::new(rows.into_iter().map(|row| (row.backend, row.tool))))
        .map_err(|error| Box::new(unavailable(&error)))
}

/// 503 for a token or opt-out lookup that failed: the caller cannot be
/// authenticated, which is not the same as being refused.
fn unavailable(error: &StoreError) -> Response {
    tracing::error!(%error, "Token authentication failed");
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> Option<IpAddr> {
        text.parse().ok()
    }

    #[test]
    fn a_jwt_has_three_base64url_parts() {
        assert!(looks_like_jwt(
            "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln-_"
        ));
        for other in [
            "",
            "a.b",
            "a.b.c.d",
            "a..c",
            "axon_pat_x",
            "a.b.c=",
            "a b.c.d",
        ] {
            assert!(!looks_like_jwt(other), "{other:?}");
        }
    }

    #[test]
    fn a_public_peer_is_used_as_is() {
        // client-supplied forwarding headers are not believed
        assert_eq!(
            select_client_ip(ip("203.0.113.5"), "198.51.100.1").as_deref(),
            Some("203.0.113.5")
        );
    }

    #[test]
    fn a_proxy_peer_hands_over_the_rightmost_parseable_entry() {
        for peer in [
            "127.0.0.1",
            "::1",
            "10.1.2.3",
            "192.168.0.9",
            "172.16.0.1",
            "fd12::1",
        ] {
            assert_eq!(
                select_client_ip(ip(peer), "6.6.6.6, 198.51.100.7").as_deref(),
                Some("198.51.100.7"),
                "{peer}"
            );
        }
        assert_eq!(
            select_client_ip(ip("127.0.0.1"), "198.51.100.7, unknown, ").as_deref(),
            Some("198.51.100.7")
        );
        assert_eq!(
            select_client_ip(ip("127.0.0.1"), "2001:db8::1").as_deref(),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn a_proxy_peer_without_a_usable_header_is_itself() {
        assert_eq!(
            select_client_ip(ip("127.0.0.1"), "").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            select_client_ip(ip("10.0.0.2"), "garbage").as_deref(),
            Some("10.0.0.2")
        );
    }

    #[test]
    fn no_peer_means_no_address() {
        assert_eq!(select_client_ip(None, "198.51.100.7"), None);
    }

    #[test]
    fn a_mapped_loopback_counts_as_loopback() {
        assert_eq!(
            select_client_ip(ip("::ffff:127.0.0.1"), "198.51.100.7").as_deref(),
            Some("198.51.100.7")
        );
    }
}
