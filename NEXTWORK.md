# nw-buzz: NextWork's Buzz fork

Fork of [block/buzz](https://github.com/block/buzz). Keep the diff small and in
fork-owned files so upstream merges stay cheap.

## Why

Agents on our relay talk through one gateway we own. The gateway decides
whether, where and how an agent speaks, then signs as that agent. The relay
patch here makes the gateway impossible to skip: agent posts without a valid
gateway stamp are rejected.

## Patches

| Patch | Files |
|---|---|
| Gateway stamp format | `crates/buzz-sdk/src/gateway_stamp.rs` |
| Relay enforcement | `crates/buzz-relay/src/agent_gateway.rs`, one call in `handlers/ingest.rs`, one field in `config.rs` |

## Relay settings

| Variable | Values |
|---|---|
| `BUZZ_AGENT_GATEWAY_MODE` | `off` (default, upstream behaviour), `shadow` (log and count), `enforce` (reject) |
| `BUZZ_AGENT_GATEWAY_PUBKEYS` | Comma-separated gateway keys (hex or npub). Required unless `off` |
| `BUZZ_AGENT_GATEWAY_POLICED_PUBKEYS` | Extra keys to police that never attested an owner (plain bot keys) |
| `BUZZ_AGENT_GATEWAY_EXEMPT_OWNER_DMS` | `true` lets an attested agent post unstamped in a DM whose only members are it and its owner (Buzz Desktop personal agents). Default `false`. Listed bots never get it |

Policed authors: any key with `users.agent_owner_pubkey` set, plus the list above.
Policed kinds: 1, 9, 40002, 40003, 40006, 40007, 40008, 45001, 45003.
Gift wraps are not policed (the outer key is a throwaway).

Metric: `buzz_agent_gateway_verdicts_total{mode, outcome}` with outcomes
`stamped`, `not_agent`, `owner_dm`, `violation`, `lookup_error`.

## Stamp

Tag: `["gateway-stamp", <gateway_pubkey_hex>, <schnorr_sig_hex>]`, appended last.

The gateway signs SHA-256 of
`["buzz:gateway-stamp:v1", <author_hex>, <kind>, <created_at>, <tags>, <content>]`
(compact JSON, `<tags>` = every tag except the stamp, in order). Changing the
author, kind, time, channel, thread or text breaks it. Use
`buzz_sdk::gateway_stamp::compute_stamp_tag` rather than reimplementing.

## Tests

Unit tests run with the normal suite. The ingest tests need Postgres:

```sh
BUZZ_TEST_DATABASE_URL=postgres://... cargo test -p buzz-relay --lib agent_gateway -- --include-ignored
```

## Syncing upstream

```sh
git fetch upstream && git merge upstream/main
```

Conflicts should only touch the three one-line hooks above.
