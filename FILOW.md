# Filow patches on matrix-rust-sdk

This branch is `matrix-sdk-0.19.1` (upstream tag, commit `b18166c68`) plus
the patches Filow needs and upstream does not ship. It is **not maintained**
and not used by Filow yet: Filow builds against the released crates. Integrate
it when it's needed (see "Integrating it into Filow").

Tracking issue: https://github.com/loisBreant/Filow/issues/106

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
