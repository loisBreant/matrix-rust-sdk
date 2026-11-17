# Filow patches on matrix-rust-sdk

This branch is `matrix-sdk-0.19.1` (upstream tag, commit `b18166c68`) plus
the patches Filow needs and upstream does not ship. Filow pins a commit of it
in the `[patch.crates-io]` tables of `client_core/Cargo.toml` and
`app/src-tauri/Cargo.toml` (Filow ADR 0025); each new patch is a new commit
here and a new pin there.

Tracking issues: https://github.com/loisBreant/Filow/issues/106 (patch 1),
https://github.com/loisBreant/Filow/issues/537 (patch 2),
https://github.com/loisBreant/Filow/issues/1560 (patch 3)

## Patch 1: encrypt reactions in encrypted rooms

`crates/matrix-sdk/src/room/futures.rs`. Upstream sends `m.reaction` in the
clear even in an encrypted room ("Reactions are currently famously not
encrypted, skip encrypting them until they are"). `Room::send`, `send_raw` and
the send queue all take that path, and the `OlmMachine` is reachable only
through `olm_machine_for_testing` (the `testing` feature), so there is no way
around it without patching.

### Why Filow needs it

Since Filow PR #98, which addresses MSC4153 ("exclude insecure devices"), a
Filow device believes only events it can tie to a verified device. A clear
event carries no device, and the homeserver can forge one under any sender.
For that reason a clear reaction in a room that may be encrypted is dropped
(`client_core/src/matrix/timeline.rs`, `stored_timeline_event_from_event`).
That rule must stay. As a result, a reaction sent from a Filow device appears
only in its sender's local echo. The account's other devices never store it,
and the sender loses it after a resync or a backfill.

With the patch, the reaction is Megolm-encrypted like any other event. The
relation stays in the clear envelope too (`OutboundGroupSession::encrypt`
copies `m.relates_to`), as the spec requires for server-side aggregation. On
decryption, matrix-sdk-crypto and mautrix-go both prefer the relation inside
the ciphertext, so a homeserver that rewrites the clear copy cannot move the
reaction or change its key.

### Background

- Spec (client-server API, "Forming relationships between events"):
  `m.relates_to` MUST be in the cleartext of an `m.room.encrypted` event.
  The key is part of the relation, so encrypting a reaction hides the event
  type and authenticates the sender's device, but does not hide the emoji
  from the server.
- matrix-js-sdk (`shouldEncryptEventForRoom`) also leaves reactions
  unencrypted on purpose. Its reasons are push-rule notifications and
  server-side bundling, and matrix-rust-sdk#470 followed the same reasoning.
- mautrix-go bridges (mautrix-whatsapp, mautrix-gmessages) decrypt and
  forward an encrypted reaction. `bridgev2/matrix` checks the device against
  `verification_levels`, then dispatches it, and the portal calls
  `handleMatrixReaction`. They send their own reactions encrypted only with
  `encryption.msc4392: true`.

## Patch 2: rotate the fallback key on request

`crates/matrix-sdk-crypto/src/olm/account.rs`, `machine/mod.rs` and
`crates/matrix-sdk/src/encryption/mod.rs`: `Account::rotate_fallback_key`,
`OlmMachine::rotate_fallback_key` and `Encryption::rotate_fallback_key`
generate and persist a new fallback key now, whatever the age of the current
one; `Encryption::rotate_fallback_key` also uploads it at once (a failed
upload is logged and left to the next sync). Nothing is done, and `false` is
returned, while a fallback key still waits to be uploaded or before the
account made its first one.

### Why Filow needs it

A managed Filow cell restored from a backup serves the fallback key Synapse
held at the restore point. vodozemac keeps only the current and one previous
fallback key, and `generate_fallback_key_if_needed` replaces the current one
only once it is a week old, without asking which one the server holds. After
a restore more than about two rotations back, a sender who finds no one-time
key left claims a fallback key whose private half is gone, and its Olm
message cannot be decrypted. Filow calls the rotation once per restore
epoch, after a sync round that brought no to-device message: rotating drops
the previous key, which a sender may have claimed for a message still
queued for the device (Filow ADR 0044).

Test: `test_fallback_key_rotation_on_request` in `olm/account.rs`. In Filow,
`a_claim_after_a_restore_epoch_gets_a_fallback_key_the_device_holds`
(`client_core/src/key_backup/integration_tests.rs`) is red without the
rotation and green with it.

## Patch 3: share a room's key only with the own user's devices

`crates/matrix-sdk-base/src/client.rs` and `crates/matrix-sdk/src/room/mod.rs`:
`Room::share_room_keys_only_with_own_user` (and
`BaseClient::share_room_keys_only_with_own_user`) marks a room, for as long as
the client lives, so that the users whose devices get its room key are only
the own user, whatever the room's member list says when the key is shared.
`BaseClient::room_key_recipient_users` is the one place the list is made, and
the three readers of the member list on the send path use it:
`BaseClient::share_room_key`, the one-time-key claim in
`Room::preshare_room_key`, and `Room::query_keys_for_untracked_or_dirty_users`.
The client's `CollectStrategy` still picks which of the own user's devices
get the key; an outbound session already shared with someone else is rotated
at the next share, as for a member who left. The mark is in memory, shared
with `clone_with_in_memory_state_store` copies, and has no way back.

### Why Filow needs it

Filow keeps a user's AI conversations in a private Megolm room only the user
is in (Filow ADR 0102). Filow's strategy is `OnlyTrustedDevices`, which also
keys the devices of the bridge bots Filow pins (Filow ADR 0089), so it would
key a pinned bot the homeserver lists as a member. Filow checks the member
list before it sends, but the share reads the state store again, inside
`send_raw`, and a sync can land a member in between. The strategy is
client-wide (`ClientBuilder::with_room_key_recipient_strategy`) and the member
list is read inside the SDK, so neither can be narrowed for one room from
outside; upstream `main` has no per-room recipient control either
(`BaseClient::share_room_key` reads `get_user_ids` with the client's
strategy). Filow calls the method before each AI send.

Test: `test_room_keys_shared_only_with_own_user` in
`crates/matrix-sdk-base/src/client.rs`. In Filow,
`a_member_landed_between_the_check_and_the_share_gets_no_ai_room_key`
(`client_core/src/matrix/send.rs`) is red without the patch (the bot landed
mid-send gets the room key) and green with it.

## Dependency bump: rusqlite 0.42.0

`crates/matrix-sdk-sqlite/Cargo.toml` asks for `rusqlite = "0.42.0"` instead
of 0.40.2 (no code change). libsqlite3-sys declares `links = "sqlite3"`, so
this crate and Filow's client core must use the same rusqlite major. Filow
needs libsqlite3-sys 0.40 for RUSTSEC-2026-0459 (SQLite before 3.54.0 could
return uninitialized page-cache memory for a database opened with a `-wal`
file of another page size): its bundled SQLCipher 4.20.0 is built on SQLite
3.54.1. rusqlite 0.41.x is not enough (with SQLCipher, libsqlite3-sys 0.39
still builds SQLCipher 4.19.0 on SQLite 3.53.4). Upstream `main` moved to
0.41.1 with no code change either (`18757f7e08`). Filow issue:
https://github.com/loisBreant/Filow/issues/1205

## Integrating it into Filow

1. Rebase this branch onto the matrix-sdk version Filow uses, if it has moved.
2. Patch **every** matrix-rust-sdk crate in the lockfile from the same commit,
   in both `client_core/Cargo.toml` and `app/src-tauri/Cargo.toml`, because
   `[patch]` only applies at a workspace root. Patching `matrix-sdk` alone
   would pull duplicate `matrix-sdk-base`/`-crypto` crates.

   ```toml
   [patch.crates-io]
   matrix-sdk = { git = "https://github.com/loisBreant/matrix-rust-sdk", rev = "<commit>" }
   matrix-sdk-base = { git = "https://github.com/loisBreant/matrix-rust-sdk", rev = "<commit>" }
   matrix-sdk-common = { git = "https://github.com/loisBreant/matrix-rust-sdk", rev = "<commit>" }
   matrix-sdk-crypto = { git = "https://github.com/loisBreant/matrix-rust-sdk", rev = "<commit>" }
   matrix-sdk-indexeddb = { git = "https://github.com/loisBreant/matrix-rust-sdk", rev = "<commit>" }
   matrix-sdk-sqlite = { git = "https://github.com/loisBreant/matrix-rust-sdk", rev = "<commit>" }
   matrix-sdk-store-encryption = { git = "https://github.com/loisBreant/matrix-rust-sdk", rev = "<commit>" }
   ```

3. Apply `filow/client-core-tests.patch` (made against Filow `1b800761`):
   - `send.rs`: `a_reaction_in_an_encrypted_room_is_encrypted`. The reaction
     must leave as `m.room.encrypted`, with the relation in the envelope.
   - `live_synapse_redactions.rs`: a reaction sent by one device is stored by
     another device of the same account, and still there after the history is
     paginated again. It runs with `make check-live-matrix`, and its devices
     get allowlist-valid `FILOW_<32 hex>` IDs.

   Both are red on the released 0.19.1 and green with this branch (checked on
   2026-10-02 against Synapse 1.159.0).
4. Run `security-crypto-reviewer` and `architecture-guardian`: this changes
   the Megolm send path and a dependency.
