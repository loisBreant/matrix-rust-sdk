# Filow patches on matrix-rust-sdk

This branch is `matrix-sdk-0.19.1` (upstream tag, commit `b18166c68`) plus
the patches Filow needs and upstream does not ship. Filow pins a commit of it
in the `[patch.crates-io]` tables of `client_core/Cargo.toml` and
`app/src-tauri/Cargo.toml` (Filow ADR 0025); each new patch is a new commit
here and a new pin there.

Tracking issues: https://github.com/loisBreant/Filow/issues/106 (patch 1),
https://github.com/loisBreant/Filow/issues/537 (patch 2),
https://github.com/loisBreant/Filow/issues/1560 (patch 3),
https://github.com/loisBreant/Filow/issues/1685 (patches 4 and 5)

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
get the key. The mark is in memory, shared with
`clone_with_in_memory_state_store` copies, and has no way back.

A key someone else holds never encrypts an event sent after the mark:

- `Room::share_room_keys_only_with_own_user` (now `async`) discards the
  room's outbound session when another user received it or has a request
  pending to receive it (`OlmMachine::room_key_shared_only_with_own_user`).
- `Room::send`/`send_raw` (`room/futures.rs`), in a marked room, check after
  encrypting that the session used is still the room's, not invalidated, and
  shared (sent or pending) with no other user; if not, the ciphertext is
  dropped, the session discarded, the key shared again and the event
  encrypted again, once; a second failure is `Error::RoomKeySharedBeyondOwnUser`
  and nothing is sent. This closes the race the mark alone leaves: a share
  that read the member list before the mark, or that the send joined through
  `group_session_deduplicated_handler`, can still give the session to another
  member. The session id comes from the encryption result; a result without
  one fails the check. Checking after encrypting is sound because a share
  copies the room key early (`maybe_encrypt_room_key`) and records its
  pending request late (`add_request`), and every share into the room runs
  under this `Client`'s `group_session_deduplicated_handler`, which a send
  waits on before it encrypts: a share that copied the key before the
  encryption has recorded its request by the time of the check, and one
  that copies it later carries only later messages. Notification and other
  cloned clients share the mark but not that lock, so the guarantee holds
  only while the room's events are sent from one `Client`.
- Not covered: `send_state_event` encryption (`experimental-encrypted-state-events`,
  which Filow does not enable).

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

Tests: `test_room_keys_shared_only_with_own_user` in
`crates/matrix-sdk-base/src/client.rs`; in
`crates/matrix-sdk/tests/integration/encryption/own_user_only_room_keys.rs`,
a key shared with Bob before the mark, and one being sent to Bob while the
room is marked, never encrypt the next event. In Filow,
`a_member_landed_between_the_check_and_the_share_gets_no_ai_room_key`
(`client_core/src/matrix/send.rs`) is red without the patch (the bot landed
mid-send gets the room key) and green with it.

## Patch 4: import secrets from memory, and write each secret once

`crates/matrix-sdk/src/encryption/secret_storage/secret_store.rs`,
`futures.rs` and `mod.rs`, all additive:

- `SecretStore::import_cross_signing_keys(CrossSigningKeyExport)`: the
  cross-signing step of `import_secrets()` on keys the caller already holds.
  It refreshes the own identity with a `/keys/query`, imports through the
  checked `OlmMachine::import_cross_signing_keys` (each key must match the
  published one of its usage, or none is imported), signs the own device when
  the self-signing key came in, and returns the `CrossSigningStatus`.
- `SecretStore::import_backup_key(&str)`: the backup step of
  `import_secrets()` on a key the caller already holds, same error mapping
  (`InconsistentBackupDecryptionKey` when the key is not the current
  version's). Stricter than that step: a backup already enabled for the
  current version is kept only if it uses this very key
  (`Backups::enable_backups_with_key`); otherwise this key replaces it. The
  version is a label the homeserver chooses, and serving a new key under the
  label a device already backs up to would otherwise keep the device
  encrypting room keys to its old key. `maybe_enable_backups`, which
  `import_secrets()` uses, is unchanged.
- `import_secrets()` now reads the secrets, then calls those two; its
  behaviour is unchanged (`secret_storage.rs`'s
  `test_restore_cross_signing_from_secret_store` still pins it).
- `Backups::stored_backup_public_key()`: the public half of the backup
  decryption key the device stores, so a caller can tell whether the device
  backs up with another key than the one it trusts.
- `Backups::adopt_backup_key(&str)`: store and back up with the given key,
  under the version the device stores, whatever the homeserver serves as
  current; room keys are marked not backed up, so they are all encrypted to
  it from then on. A persistent fail-closed for a device backing up with a
  key the caller no longer trusts and cannot rotate off: disabling does not
  last, since matrix-sdk resumes the stored key at start. Not atomic: it
  stops the backup, stores the key, then enables it. A process stopped in
  between resumes the key stored before at the next start, which only
  means the caller's next check adopts the key again; nothing is lost and
  nothing reaches a key the caller did not give.
- `Backups::forget_backup_key()`: stop backing up, and remove the backup
  decryption key and version the device stores, leaving the homeserver's
  versions alone (and the secret inbox, which holds only secrets the device
  asked for; Filow asks for none). Nothing is
  resumed at the next start, and the device holds no backup key a device
  asking for it could be served. `Backups::disable()` deletes the version on
  the homeserver and leaves the key stored; `save_decryption_key(None,
  None)` changes nothing (`None` means "unchanged"). Underneath:
  `Changes::forget_backup_keys` in matrix-sdk-crypto, applied before a key
  or version saved in the same changes, by the memory, SQLite and IndexedDB
  stores, and `BackupMachine::forget_decryption_key()`.
- `Backups::create_with_key(&str)`: `Backups::create()` with a backup
  decryption key the caller chose, so it can record the key before the
  homeserver hears of the version. With `create()` the key is known only
  once the version exists and the device stores it.
- `SecretStore::export_cross_signing_keys()`: `export_secrets()` without the
  backup key. `export_secrets()` is that plus the backup key, as before.
- `CreateStore::with_backup_key(&str)` stores the given backup key instead
  of the device's own, and `CreateStore::without_cross_signing_keys()`
  stores no private cross-signing key. Without either, `create_secret_store()`
  exports what it exported before.

### Why Filow needs it

Filow checks secret storage against its key-backup wrap (the identity and
the backup key the wrap names) before restoring, then needs to import what
it checked. `import_secrets()` reads every secret from the homeserver again,
one GET each, and a homeserver can answer that second read with another
ciphertext it kept under the same secret-storage key: a previous identity it
publishes again, or a backup key a revoked device knew whose version it makes
current again (Filow #1685, found in review of Filow #1638). Upstream exposes
no import from memory: `get_cross_signing_keys` and `maybe_enable_backups`
are private, `Backups::maybe_enable_backups` is `pub(crate)`, the checked
`OlmMachine::import_cross_signing_keys` is reachable only through
`olm_machine_for_testing`, and `Encryption::import_secrets_bundle` imports
unchecked and needs every key (upstream `main` at `2c76c145`, 2026-11-17,
unchanged).

Moving secret storage to a new key has the same weakness in the other
direction: `Recovery::reset_key()` exports the device's own backup key and
identity, and a caller that then stores another backup key, or removes the
identity, leaves a second ciphertext of that name under the new key for the
homeserver to serve. The `CreateStore` options write each name at most once.

Filow's review of the change found two more needs. A device that holds or
trusts another identity than the one Filow's wrap names (it missed a
replacement, and the homeserver publishes the identity from before) must
stop holding any backup key, for good: matrix-sdk serves a backup key it
holds to any own device that identity signed, a revoked one included.
Hence `forget_backup_key()`. And a rotation must record the key of the
version it creates before the version exists, or a process stopped between
the creation and the record leaves the current version's only copy
unrecorded. Hence `create_with_key()`.

Tests: `crates/matrix-sdk/tests/integration/encryption/secrets_from_memory.rs`
(each import reads nothing from secret storage, a key of another identity or
a malformed one imports nothing, a backup key that is not current is
refused, a key served under the label of the version already enabled
replaces the old one, each `CreateStore` option, the unchanged defaults, a
forgotten backup key is neither held nor resumed, a version is created with
the key given) and `test_backup_keys_forgetting` in matrix-sdk-crypto's
store integration tests (memory and SQLite stores). In Filow,
the #1685 tests in `client_core/src/key_backup/cross_signing_tests.rs` serve
another ciphertext on every read after the first, and are red without the
patch's use; `a_device_trusting_another_identity_takes_up_no_backup_key` and
`a_rotation_records_its_backup_key_before_creating_the_version` are red
without the last two additions' use.

## Patch 5: answer no secret request

`crates/matrix-sdk-crypto/src/gossiping/machine.rs` and `Cargo.toml`: with
the new feature `refuse-secret-requests`, `GossipMachine::handle_secret_request`
serves no `m.secret.request`, whatever the requesting device and its trust.
Off by default, so matrix-sdk-crypto's own behaviour and tests are
unchanged; Filow's client core turns it on in its `matrix-sdk-crypto`
dependency.

### Why Filow needs it

matrix-sdk-crypto serves a secret it holds (the backup decryption key, the
private cross-signing keys) to any own device that is verified, and a
device signed by the account's self-signing key is verified whatever its
local trust (`handle_secret_request`; matrix-sdk-crypto 0.19 has no setting
for it). The homeserver can forge such a request in a revoked device's
name, and the answer, Olm-encrypted to that device's key, reaches it. A
device that missed an identity replacement, or the device that made a
rotation while the replacement is still owed, still trusts the identity a
revoked device was signed by, so a revoked device could obtain the current
backup key (Filow #1685, review finding H-1). Filow devices never need
secret gossip: every secret they share travels through secret storage,
opened with the account key. Upstream `main` (`33af1f68`, 2026-11-18) has
no switch for it either: `handle_secret_request` still serves any verified
own device.

Tests: `test_secret_requests_are_refused` in `gossiping/machine.rs` (run
with `--features refuse-secret-requests`), and `test_secret_share_cycle`,
which serves the secret without the feature and refuses it with it. In Filow, `no_device_serves_a_secret_to_a_cross_signed_own_device`
(`client_core/src/key_backup/gossip_tests.rs`) is red without the feature.

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
