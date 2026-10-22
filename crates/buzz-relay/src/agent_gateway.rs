//! Agent gateway enforcement (NextWork fork).
//!
//! When enabled, message-like events authored by agent keys must carry a
//! valid gateway stamp (see [`buzz_sdk::gateway_stamp`]). The gateway is the
//! single service that decides whether, where and how an agent speaks; this
//! check makes it impossible for an agent key to post around it.
//!
//! An author is policed when `users.agent_owner_pubkey` is set (a NIP-OA
//! attested agent) or when its pubkey is listed in
//! `BUZZ_AGENT_GATEWAY_POLICED_PUBKEYS` (bots that never attested an owner).
//!
//! Modes (`BUZZ_AGENT_GATEWAY_MODE`):
//! - `off` (default): no checks, no DB lookups. Upstream behaviour.
//! - `shadow`: unstamped agent posts are accepted, logged and counted.
//! - `enforce`: unstamped agent posts are rejected.
//!
//! Gift wraps are not policed: their outer pubkey is a throwaway key, so the
//! real author is not visible to the relay.

use std::collections::HashSet;

use buzz_core::kind::{
    KIND_FORUM_COMMENT, KIND_FORUM_POST, KIND_STREAM_MESSAGE, KIND_STREAM_MESSAGE_DIFF,
    KIND_STREAM_MESSAGE_EDIT, KIND_STREAM_MESSAGE_SCHEDULED, KIND_STREAM_MESSAGE_V2,
    KIND_STREAM_REMINDER, KIND_TEXT_NOTE,
};
use buzz_core::TenantContext;
use buzz_sdk::gateway_stamp::{verify_event_stamp, StampError};
use nostr::{Event, PublicKey};
use tracing::warn;

use crate::config::ConfigError;
use crate::handlers::ingest::IngestError;
use crate::state::AppState;

/// How the relay treats unstamped agent posts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AgentGatewayMode {
    /// No checks.
    #[default]
    Off,
    /// Accept, but log and count violations.
    Shadow,
    /// Reject violations.
    Enforce,
}

impl AgentGatewayMode {
    fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }
}

/// Agent gateway settings, read from the environment at startup.
#[derive(Debug, Clone, Default)]
pub struct AgentGatewayConfig {
    /// Enforcement mode.
    pub mode: AgentGatewayMode,
    /// Gateway keys whose stamps are accepted.
    pub gateway_pubkeys: Vec<PublicKey>,
    /// Extra authors to police even without an attested owner.
    pub policed_pubkeys: HashSet<PublicKey>,
}

impl AgentGatewayConfig {
    /// Read `BUZZ_AGENT_GATEWAY_MODE`, `BUZZ_AGENT_GATEWAY_PUBKEYS` and
    /// `BUZZ_AGENT_GATEWAY_POLICED_PUBKEYS`.
    ///
    /// # Errors
    ///
    /// Fails on an unknown mode, a malformed pubkey, or a non-off mode with
    /// no gateway keys (every agent post would be rejected).
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::parse(|name| std::env::var(name).ok())
    }

    fn parse(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mode = match get("BUZZ_AGENT_GATEWAY_MODE")
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            None | Some("") | Some("off") => AgentGatewayMode::Off,
            Some("shadow") => AgentGatewayMode::Shadow,
            Some("enforce") => AgentGatewayMode::Enforce,
            Some(other) => {
                return Err(ConfigError::InvalidValue(format!(
                    "BUZZ_AGENT_GATEWAY_MODE must be off, shadow or enforce, got {other:?}"
                )))
            }
        };
        let gateway_pubkeys = parse_pubkeys(&get, "BUZZ_AGENT_GATEWAY_PUBKEYS")?;
        let policed_pubkeys = parse_pubkeys(&get, "BUZZ_AGENT_GATEWAY_POLICED_PUBKEYS")?
            .into_iter()
            .collect();
        if mode != AgentGatewayMode::Off && gateway_pubkeys.is_empty() {
            return Err(ConfigError::InvalidValue(
                "BUZZ_AGENT_GATEWAY_MODE is on but BUZZ_AGENT_GATEWAY_PUBKEYS is empty".into(),
            ));
        }
        Ok(Self {
            mode,
            gateway_pubkeys,
            policed_pubkeys,
        })
    }
}

fn parse_pubkeys(
    get: &impl Fn(&str) -> Option<String>,
    name: &str,
) -> Result<Vec<PublicKey>, ConfigError> {
    let Some(raw) = get(name) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let pk = PublicKey::parse(entry).map_err(|e| {
            ConfigError::InvalidValue(format!("{name} entry {entry:?} is not a pubkey: {e}"))
        })?;
        if !out.contains(&pk) {
            out.push(pk);
        }
    }
    Ok(out)
}

/// Event kinds through which an agent can say something to people.
pub fn is_policed_kind(kind: u32) -> bool {
    matches!(
        kind,
        KIND_TEXT_NOTE
            | KIND_STREAM_MESSAGE
            | KIND_STREAM_MESSAGE_V2
            | KIND_STREAM_MESSAGE_EDIT
            | KIND_STREAM_MESSAGE_SCHEDULED
            | KIND_STREAM_REMINDER
            | KIND_STREAM_MESSAGE_DIFF
            | KIND_FORUM_POST
            | KIND_FORUM_COMMENT
    )
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Allow,
    Violation,
}

fn decide(is_agent: bool, stamp: &Result<PublicKey, StampError>) -> Verdict {
    if !is_agent || stamp.is_ok() {
        Verdict::Allow
    } else {
        Verdict::Violation
    }
}

fn count(mode: AgentGatewayMode, outcome: &'static str) {
    metrics::counter!(
        "buzz_agent_gateway_verdicts_total",
        "mode" => mode.label(),
        "outcome" => outcome
    )
    .increment(1);
}

/// Ingest gate. Called for every event after the channel membership check.
///
/// # Errors
///
/// In enforce mode, rejects unstamped agent posts and fails closed when the
/// agent lookup errors.
pub(crate) async fn check(
    state: &AppState,
    tenant: &TenantContext,
    event: &Event,
    kind: u32,
) -> Result<(), IngestError> {
    let cfg = &state.config.agent_gateway;
    if cfg.mode == AgentGatewayMode::Off || !is_policed_kind(kind) {
        return Ok(());
    }

    let stamp = verify_event_stamp(event, &cfg.gateway_pubkeys);
    if stamp.is_ok() {
        count(cfg.mode, "stamped");
        return Ok(());
    }

    // Uncached on purpose: a stale or error-poisoned "human" entry would let
    // an agent through. Only unstamped writes pay for this lookup.
    let is_agent = if cfg.policed_pubkeys.contains(&event.pubkey) {
        true
    } else {
        match state
            .db
            .get_agent_channel_policy(tenant.community(), &event.pubkey.to_bytes())
            .await
        {
            Ok(row) => row.is_some_and(|(_, owner)| owner.is_some()),
            Err(e) if cfg.mode == AgentGatewayMode::Enforce => {
                count(cfg.mode, "lookup_error");
                return Err(IngestError::Internal(format!(
                    "error: internal error checking agent gateway policy: {e}"
                )));
            }
            Err(e) => {
                count(cfg.mode, "lookup_error");
                warn!(error = %e, "agent gateway: agent lookup failed in shadow mode");
                return Ok(());
            }
        }
    };

    if decide(is_agent, &stamp) == Verdict::Allow {
        count(cfg.mode, "not_agent");
        return Ok(());
    }

    let reason = stamp.err().map(|e| e.to_string()).unwrap_or_default();
    count(cfg.mode, "violation");
    warn!(
        author = %event.pubkey,
        kind,
        event_id = %event.id,
        mode = cfg.mode.label(),
        %reason,
        "agent gateway: agent post without a valid stamp"
    );
    match cfg.mode {
        AgentGatewayMode::Enforce => Err(IngestError::AuthFailed(format!(
            "restricted: agent posts must go through the agent gateway ({reason})"
        ))),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        }
    }

    const PK: &str = "cfe6a28af841f076c747d11cb7b0233d711e11e5f03d025cf386601235eaba46";

    #[test]
    fn defaults_to_off() {
        let cfg = AgentGatewayConfig::parse(env(&[])).unwrap();
        assert_eq!(cfg.mode, AgentGatewayMode::Off);
        assert!(cfg.gateway_pubkeys.is_empty());
    }

    #[test]
    fn on_without_gateway_keys_refuses_startup() {
        for mode in ["shadow", "enforce"] {
            let res = AgentGatewayConfig::parse(env(&[("BUZZ_AGENT_GATEWAY_MODE", mode)]));
            assert!(res.is_err(), "{mode} with no keys must fail");
        }
    }

    #[test]
    fn unknown_mode_refuses_startup() {
        let res = AgentGatewayConfig::parse(env(&[
            ("BUZZ_AGENT_GATEWAY_MODE", "enforcing"),
            ("BUZZ_AGENT_GATEWAY_PUBKEYS", PK),
        ]));
        assert!(res.is_err());
    }

    #[test]
    fn malformed_pubkey_refuses_startup() {
        let res = AgentGatewayConfig::parse(env(&[
            ("BUZZ_AGENT_GATEWAY_MODE", "shadow"),
            ("BUZZ_AGENT_GATEWAY_PUBKEYS", "nothex"),
        ]));
        assert!(res.is_err());
    }

    #[test]
    fn parses_enforce_with_keys() {
        let cfg = AgentGatewayConfig::parse(env(&[
            ("BUZZ_AGENT_GATEWAY_MODE", " Enforce "),
            ("BUZZ_AGENT_GATEWAY_PUBKEYS", &format!("{PK}, {PK}")),
            ("BUZZ_AGENT_GATEWAY_POLICED_PUBKEYS", PK),
        ]))
        .unwrap();
        assert_eq!(cfg.mode, AgentGatewayMode::Enforce);
        assert_eq!(cfg.gateway_pubkeys.len(), 1, "duplicates collapse");
        assert_eq!(cfg.policed_pubkeys.len(), 1);
    }

    #[test]
    fn polices_message_kinds_only() {
        assert!(is_policed_kind(KIND_STREAM_MESSAGE));
        assert!(is_policed_kind(KIND_STREAM_MESSAGE_EDIT));
        assert!(is_policed_kind(KIND_FORUM_POST));
        assert!(!is_policed_kind(buzz_core::kind::KIND_REACTION));
        assert!(!is_policed_kind(buzz_core::kind::KIND_GIFT_WRAP));
    }

    #[test]
    fn verdicts() {
        let ok: Result<PublicKey, StampError> = Ok(PublicKey::parse(PK).unwrap());
        let missing: Result<PublicKey, StampError> = Err(StampError::Missing);
        assert_eq!(
            decide(false, &missing),
            Verdict::Allow,
            "humans are never policed"
        );
        assert_eq!(decide(true, &ok), Verdict::Allow);
        assert_eq!(decide(true, &missing), Verdict::Violation);
    }
}

/// Production-path tests: a real `ingest_event` against Postgres.
#[cfg(test)]
mod postgres_tests {
    use std::sync::Arc;

    use buzz_core::TenantContext;
    use buzz_sdk::gateway_stamp::compute_stamp_tag;
    use nostr::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};
    use uuid::Uuid;

    use super::*;
    use crate::handlers::group_state_postgres_tests::{
        community, create_channel, http_auth, state,
    };
    use crate::handlers::ingest::{ingest_event, IngestError};

    struct Fixture {
        state: Arc<AppState>,
        tenant: TenantContext,
        gateway: Keys,
        owner: Keys,
        agent: Keys,
        bot: Keys,
        channel: Uuid,
    }

    async fn fixture(mode: AgentGatewayMode) -> Fixture {
        let (gateway, owner, agent, bot) = (
            Keys::generate(),
            Keys::generate(),
            Keys::generate(),
            Keys::generate(),
        );
        let base = state().await;
        let mut config = (*base.config).clone();
        config.agent_gateway = AgentGatewayConfig {
            mode,
            gateway_pubkeys: vec![gateway.public_key()],
            policed_pubkeys: [bot.public_key()].into_iter().collect(),
        };
        let mut patched = (*base).clone();
        patched.config = Arc::new(config);
        let state = Arc::new(patched);

        let tenant = community(&state, "agent-gateway").await;
        let channel = create_channel(
            &state,
            &tenant,
            &owner,
            &[
                &["p", &agent.public_key().to_hex()],
                &["p", &bot.public_key().to_hex()],
            ],
        )
        .await;
        let agent_bytes = agent.public_key().to_bytes();
        for pubkey in [owner.public_key().to_bytes(), agent_bytes] {
            state
                .db
                .ensure_user(tenant.community(), &pubkey)
                .await
                .expect("ensure user");
        }
        state
            .db
            .set_agent_owner(
                tenant.community(),
                &agent_bytes,
                &owner.public_key().to_bytes(),
            )
            .await
            .expect("set agent owner");
        Fixture {
            state,
            tenant,
            gateway,
            owner,
            agent,
            bot,
            channel,
        }
    }

    fn message(author: &Keys, channel: Uuid, stamp_with: Option<&Keys>) -> Event {
        let kind = Kind::Custom(9);
        let created_at = Timestamp::now();
        let mut tags = vec![Tag::parse(["h", &channel.to_string()]).unwrap()];
        if let Some(gateway) = stamp_with {
            let stamp =
                compute_stamp_tag(gateway, &author.public_key(), kind, created_at, &tags, "hi")
                    .unwrap();
            tags.push(stamp);
        }
        EventBuilder::new(kind, "hi")
            .tags(tags)
            .custom_created_at(created_at)
            .sign_with_keys(author)
            .unwrap()
    }

    async fn send(
        f: &Fixture,
        author: &Keys,
        stamp_with: Option<&Keys>,
    ) -> Result<(), IngestError> {
        let event = message(author, f.channel, stamp_with);
        ingest_event(&f.state, &f.tenant, event, http_auth(author))
            .await
            .map(|_| ())
    }

    fn is_gateway_rejection(res: &Result<(), IngestError>) -> bool {
        matches!(res, Err(IngestError::AuthFailed(m)) if m.contains("agent gateway"))
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn enforce_rejects_unstamped_agent_posts() {
        let f = fixture(AgentGatewayMode::Enforce).await;
        let res = send(&f, &f.agent, None).await;
        assert!(is_gateway_rejection(&res), "unstamped agent post: {res:?}");
        let res = send(&f, &f.bot, None).await;
        assert!(
            is_gateway_rejection(&res),
            "listed bot without owner: {res:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn enforce_accepts_stamped_agent_and_human_posts() {
        let f = fixture(AgentGatewayMode::Enforce).await;
        let gateway = f.gateway.clone();
        let res = send(&f, &f.agent, Some(&gateway)).await;
        assert!(res.is_ok(), "stamped agent post: {res:?}");
        let res = send(&f, &f.owner, None).await;
        assert!(res.is_ok(), "human post: {res:?}");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn enforce_rejects_stamp_from_untrusted_gateway() {
        let f = fixture(AgentGatewayMode::Enforce).await;
        let rogue = Keys::generate();
        let res = send(&f, &f.agent, Some(&rogue)).await;
        assert!(is_gateway_rejection(&res), "rogue stamp: {res:?}");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn shadow_and_off_accept_unstamped_agent_posts() {
        for mode in [AgentGatewayMode::Shadow, AgentGatewayMode::Off] {
            let f = fixture(mode).await;
            let res = send(&f, &f.agent, None).await;
            assert!(res.is_ok(), "{mode:?}: {res:?}");
        }
    }
}
