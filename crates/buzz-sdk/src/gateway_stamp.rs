//! Agent gateway stamps (NextWork fork).
//!
//! A gateway stamp proves that an outbound agent event was approved by a
//! trusted gateway before the agent's key signed it. The gateway signs a
//! digest of everything that reaches readers (author, kind, timestamp, tags,
//! content), so a stamp cannot be moved to a different channel, thread, or
//! message body.
//!
//! Wire form: `["gateway-stamp", "<gateway_pubkey_hex>", "<schnorr_sig_hex>"]`
//!
//! Preimage: SHA-256 of the compact JSON array
//! `["buzz:gateway-stamp:v1", <author_hex>, <kind>, <created_at>, <tags>, <content>]`
//! where `<tags>` is every tag on the event except the stamp itself, in event
//! order. This mirrors NIP-01 event-id serialization, so the digest is
//! deterministic for any client that can compute an event id.

use core::str::FromStr;

use nostr::hashes::sha256::Hash as Sha256Hash;
use nostr::hashes::Hash;
use nostr::secp256k1::schnorr::Signature;
use nostr::secp256k1::Message;
use nostr::{Event, Keys, Kind, PublicKey, Tag, Timestamp, SECP256K1};

use crate::SdkError;

/// Tag name carrying a gateway stamp.
pub const GATEWAY_STAMP_TAG: &str = "gateway-stamp";

const PREIMAGE_DOMAIN: &str = "buzz:gateway-stamp:v1";

/// Why an event's gateway stamp failed verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StampError {
    /// The event carries no `gateway-stamp` tag.
    #[error("no gateway stamp")]
    Missing,
    /// The event carries more than one `gateway-stamp` tag.
    #[error("more than one gateway stamp")]
    Multiple,
    /// The stamp tag is structurally invalid.
    #[error("malformed gateway stamp: {0}")]
    Malformed(String),
    /// The stamp was signed by a key that is not a trusted gateway.
    #[error("gateway {0} is not trusted")]
    UntrustedGateway(String),
    /// The signature does not match the event's author, kind, time, tags or content.
    #[error("gateway stamp does not match this event")]
    BadSignature,
}

fn is_stamp_tag(tag: &Tag) -> bool {
    tag.as_slice().first().map(String::as_str) == Some(GATEWAY_STAMP_TAG)
}

fn stamp_digest(
    author: &PublicKey,
    kind: Kind,
    created_at: Timestamp,
    tags: &[&Tag],
    content: &str,
) -> Message {
    let tags: Vec<&[String]> = tags.iter().map(|t| t.as_slice()).collect();
    let preimage = serde_json::json!([
        PREIMAGE_DOMAIN,
        author.to_hex(),
        kind.as_u16(),
        created_at.as_secs(),
        tags,
        content,
    ])
    .to_string();
    Message::from_digest(Sha256Hash::hash(preimage.as_bytes()).to_byte_array())
}

/// Compute the stamp tag for an event the gateway is about to have signed.
///
/// `tags` must be the event's final tags in their final order. Append the
/// returned tag after them, then sign with the author's key using the same
/// `created_at`.
///
/// # Errors
///
/// Returns [`SdkError::InvalidInput`] if `tags` already contains a stamp.
pub fn compute_stamp_tag(
    gateway_keys: &Keys,
    author: &PublicKey,
    kind: Kind,
    created_at: Timestamp,
    tags: &[Tag],
    content: &str,
) -> Result<Tag, SdkError> {
    if tags.iter().any(is_stamp_tag) {
        return Err(SdkError::InvalidInput(
            "tags already contain a gateway stamp".into(),
        ));
    }
    let refs: Vec<&Tag> = tags.iter().collect();
    let message = stamp_digest(author, kind, created_at, &refs, content);
    let sig = gateway_keys.sign_schnorr(&message);
    Tag::parse([
        GATEWAY_STAMP_TAG.to_string(),
        gateway_keys.public_key().to_hex(),
        sig.to_string(),
    ])
    .map_err(|e| SdkError::InvalidTag(e.to_string()))
}

/// Verify an event's gateway stamp against a set of trusted gateway keys.
///
/// Returns the gateway pubkey that stamped the event.
///
/// # Errors
///
/// Returns a [`StampError`] describing why the event is not validly stamped.
pub fn verify_event_stamp(event: &Event, trusted: &[PublicKey]) -> Result<PublicKey, StampError> {
    let mut stamps = event.tags.iter().filter(|t| is_stamp_tag(t));
    let stamp = stamps.next().ok_or(StampError::Missing)?;
    if stamps.next().is_some() {
        return Err(StampError::Multiple);
    }

    let fields = stamp.as_slice();
    if fields.len() != 3 {
        return Err(StampError::Malformed(format!(
            "expected 3 elements, got {}",
            fields.len()
        )));
    }
    let gateway = PublicKey::from_hex(&fields[1])
        .map_err(|e| StampError::Malformed(format!("gateway pubkey: {e}")))?;
    if !trusted.contains(&gateway) {
        return Err(StampError::UntrustedGateway(gateway.to_hex()));
    }
    let sig = Signature::from_str(&fields[2])
        .map_err(|e| StampError::Malformed(format!("signature: {e}")))?;

    let rest: Vec<&Tag> = event.tags.iter().filter(|t| !is_stamp_tag(t)).collect();
    let message = stamp_digest(
        &event.pubkey,
        event.kind,
        event.created_at,
        &rest,
        &event.content,
    );
    let xonly = gateway
        .xonly()
        .map_err(|e| StampError::Malformed(format!("gateway pubkey: {e}")))?;
    SECP256K1
        .verify_schnorr(&sig, &message, &xonly)
        .map_err(|_| StampError::BadSignature)?;
    Ok(gateway)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::EventBuilder;

    fn tag(parts: &[&str]) -> Tag {
        Tag::parse(parts.iter().copied()).unwrap()
    }

    /// Build an event the way the gateway will: final tags, stamp, then sign as the agent.
    fn stamped(gateway: &Keys, agent: &Keys, content: &str, tags: Vec<Tag>) -> Event {
        let created_at = Timestamp::from(1_760_000_000);
        let kind = Kind::Custom(9);
        let stamp = compute_stamp_tag(
            gateway,
            &agent.public_key(),
            kind,
            created_at,
            &tags,
            content,
        )
        .unwrap();
        let mut all = tags;
        all.push(stamp);
        EventBuilder::new(kind, content)
            .tags(all)
            .custom_created_at(created_at)
            .sign_with_keys(agent)
            .unwrap()
    }

    fn rebuild(event: &Event, agent: &Keys, content: &str, tags: Vec<Tag>) -> Event {
        EventBuilder::new(event.kind, content)
            .tags(tags)
            .custom_created_at(event.created_at)
            .sign_with_keys(agent)
            .unwrap()
    }

    #[test]
    fn round_trip_verifies() {
        let (gw, agent) = (Keys::generate(), Keys::generate());
        let ev = stamped(&gw, &agent, "hello", vec![tag(&["h", "chan-a"])]);
        assert_eq!(
            verify_event_stamp(&ev, &[gw.public_key()]),
            Ok(gw.public_key())
        );
    }

    #[test]
    fn missing_stamp_is_rejected() {
        let agent = Keys::generate();
        let ev = EventBuilder::new(Kind::Custom(9), "hi")
            .sign_with_keys(&agent)
            .unwrap();
        assert_eq!(verify_event_stamp(&ev, &[]), Err(StampError::Missing));
    }

    #[test]
    fn untrusted_gateway_is_rejected() {
        let (gw, other, agent) = (Keys::generate(), Keys::generate(), Keys::generate());
        let ev = stamped(&gw, &agent, "hi", vec![tag(&["h", "chan-a"])]);
        assert!(matches!(
            verify_event_stamp(&ev, &[other.public_key()]),
            Err(StampError::UntrustedGateway(_))
        ));
    }

    #[test]
    fn edited_content_breaks_stamp() {
        let (gw, agent) = (Keys::generate(), Keys::generate());
        let ev = stamped(&gw, &agent, "approved text", vec![tag(&["h", "chan-a"])]);
        let tampered = rebuild(
            &ev,
            &agent,
            "something else",
            ev.tags.iter().cloned().collect(),
        );
        assert_eq!(
            verify_event_stamp(&tampered, &[gw.public_key()]),
            Err(StampError::BadSignature)
        );
    }

    #[test]
    fn moved_channel_breaks_stamp() {
        let (gw, agent) = (Keys::generate(), Keys::generate());
        let ev = stamped(&gw, &agent, "hi", vec![tag(&["h", "chan-a"])]);
        let stamp = ev.tags.iter().find(|t| is_stamp_tag(t)).unwrap().clone();
        let moved = rebuild(&ev, &agent, "hi", vec![tag(&["h", "chan-b"]), stamp]);
        assert_eq!(
            verify_event_stamp(&moved, &[gw.public_key()]),
            Err(StampError::BadSignature)
        );
    }

    #[test]
    fn stamp_reused_by_another_agent_fails() {
        let (gw, agent, thief) = (Keys::generate(), Keys::generate(), Keys::generate());
        let ev = stamped(&gw, &agent, "hi", vec![tag(&["h", "chan-a"])]);
        let reused = rebuild(&ev, &thief, "hi", ev.tags.iter().cloned().collect());
        assert_eq!(
            verify_event_stamp(&reused, &[gw.public_key()]),
            Err(StampError::BadSignature)
        );
    }

    #[test]
    fn duplicate_stamps_are_rejected() {
        let (gw, agent) = (Keys::generate(), Keys::generate());
        let ev = stamped(&gw, &agent, "hi", vec![]);
        let stamp = ev.tags.iter().find(|t| is_stamp_tag(t)).unwrap().clone();
        let doubled = rebuild(&ev, &agent, "hi", vec![stamp.clone(), stamp]);
        assert_eq!(
            verify_event_stamp(&doubled, &[gw.public_key()]),
            Err(StampError::Multiple)
        );
    }

    #[test]
    fn compute_refuses_pre_stamped_tags() {
        let gw = Keys::generate();
        let existing = tag(&[GATEWAY_STAMP_TAG, "x", "y"]);
        let res = compute_stamp_tag(
            &gw,
            &gw.public_key(),
            Kind::Custom(9),
            Timestamp::from(1),
            &[existing],
            "",
        );
        assert!(res.is_err());
    }
}
