//! Filow patch 7: `Room::bind_room_key_recipients`. A room key goes only to
//! the users and devices the room's binding permits: a member who joins after
//! the binding, a device a bound user gains, and a session someone outside
//! the binding holds never carry an event sent while it is in place. An
//! unbound room shares as upstream does.

use std::{sync::Arc, time::Duration};

use matrix_sdk::{
    Client, Room, encryption::RoomKeyRecipientBinding, test_utils::mocks::MatrixMockServer,
};
use matrix_sdk_test::{JoinedRoomBuilder, async_test, event_factory::EventFactory};
use ruma::{
    OwnedUserId, RoomId, RoomVersionId, device_id, event_id,
    events::room::message::RoomMessageEventContent, room_id,
};
use serde_json::Value;
use wiremock::{
    Mock, Request, Respond, ResponseTemplate,
    matchers::{method, path_regex},
};

/// Alice and Bob, both with a device each other knows, in an encrypted room.
/// Bob is a member from the start when `bob_joined`; otherwise only Alice is,
/// and [`bob_joins`] lands Bob's membership with a later sync.
async fn alice_and_bob(
    server: &MatrixMockServer,
    room_id: &RoomId,
    bob_joined: bool,
) -> (Client, Client) {
    server.mock_crypto_endpoints_preset().await;
    let (alice, bob) = server.set_up_alice_and_bob_for_encryption().await;
    let alice_id = alice.user_id().unwrap().to_owned();
    let bob_id = bob.user_id().unwrap().to_owned();
    let f = EventFactory::new().room(room_id).sender(&alice_id);
    let mut members = vec![f.member(&alice_id).into_raw()];
    if bob_joined {
        members.push(f.member(&bob_id).into_raw());
    }
    server.mock_get_members().ok(members).mount().await;
    server.mock_room_send().ok(event_id!("$sent")).mount().await;
    server
        .mock_sync()
        .ok_and_run(&alice, |builder| {
            let mut room = JoinedRoomBuilder::new(room_id)
                .add_state_event(f.create(&alice_id, RoomVersionId::V1))
                .add_state_event(f.room_encryption())
                .add_state_event(f.member(&alice_id));
            if bob_joined {
                room = room.add_state_event(f.member(&bob_id));
            }
            builder.add_joined_room(room);
        })
        .await;
    mount_send_to_device(server).await;
    (alice, bob)
}

/// A sync that lands Bob's membership in the room, as a homeserver can at
/// any moment.
async fn bob_joins(server: &MatrixMockServer, alice: &Client, bob: &Client, room_id: &RoomId) {
    let bob_id = bob.user_id().unwrap().to_owned();
    let f = EventFactory::new().room(room_id).sender(&bob_id);
    server
        .mock_sync()
        .ok_and_run(alice, |builder| {
            builder.add_joined_room(
                JoinedRoomBuilder::new(room_id).add_timeline_event(f.member(&bob_id)),
            );
        })
        .await;
    assert!(
        alice.get_room(room_id).unwrap().get_member_no_sync(&bob_id).await.unwrap().is_some(),
        "Bob is a member"
    );
}

/// Accepts every `/sendToDevice`, whichever client's token it carries.
async fn mount_send_to_device(server: &MatrixMockServer) {
    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/client/v3/sendToDevice/.*/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(server.server())
        .await;
}

/// The Megolm session of every encrypted event sent so far, in order.
async fn sent_sessions(server: &MatrixMockServer) -> Vec<String> {
    server
        .server()
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path().contains("/send/m.room.encrypted/"))
        .map(|request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            body["session_id"].as_str().unwrap().to_owned()
        })
        .collect()
}

/// Every `user|device` an Olm-encrypted to-device message (a room key) was
/// addressed to, after the first `skip` requests.
async fn keyed_after(server: &MatrixMockServer, skip: usize) -> Vec<String> {
    let requests = server.server().received_requests().await.unwrap();
    requests[skip..]
        .iter()
        .filter(|request| request.url.path().contains("/sendToDevice/m.room.encrypted/"))
        .flat_map(|request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            body["messages"]
                .as_object()
                .unwrap()
                .iter()
                .flat_map(|(user, devices)| {
                    devices
                        .as_object()
                        .unwrap()
                        .keys()
                        .map(move |device| format!("{user}|{device}"))
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

async fn requests_so_far(server: &MatrixMockServer) -> usize {
    server.server().received_requests().await.unwrap().len()
}

fn user(client: &Client) -> OwnedUserId {
    client.user_id().unwrap().to_owned()
}

fn bound_to(users: &[&Client]) -> RoomKeyRecipientBinding {
    let mut binding = RoomKeyRecipientBinding::new();
    for client in users {
        binding.allow_user(user(client));
    }
    binding
}

fn keys_user(keyed: &[String], client: &Client) -> bool {
    let prefix = format!("{}|", user(client));
    keyed.iter().any(|recipient| recipient.starts_with(&prefix))
}

async fn send(room: &Room, body: &str) -> matrix_sdk::Result<()> {
    room.send(RoomMessageEventContent::text_plain(body)).await.map(|_| ())
}

#[async_test]
async fn test_an_unbound_room_keys_a_member_who_joined_late() {
    // The control for the next test: the same setup without a binding keys
    // Bob, as upstream does.
    let room_id = room_id!("!portal:example.org");
    let server = MatrixMockServer::new().await;
    let (alice, bob) = alice_and_bob(&server, room_id, false).await;
    let room = alice.get_room(room_id).unwrap();
    bob_joins(&server, &alice, &bob, room_id).await;
    let start = requests_so_far(&server).await;

    send(&room, "unbound").await.unwrap();

    assert!(keys_user(&keyed_after(&server, start).await, &bob), "Bob got no key");
    assert!(room.room_key_recipient_binding().is_none());
}

#[async_test]
async fn test_a_member_who_joined_after_the_binding_gets_no_room_key() {
    let room_id = room_id!("!portal:example.org");
    let server = MatrixMockServer::new().await;
    let (alice, bob) = alice_and_bob(&server, room_id, false).await;
    let room = alice.get_room(room_id).unwrap();

    // The client checked the members (Alice alone) and bound the key to
    // them; Bob joins between that check and the share.
    room.bind_room_key_recipients(bound_to(&[&alice]));
    bob_joins(&server, &alice, &bob, room_id).await;
    let start = requests_so_far(&server).await;

    send(&room, "bound").await.unwrap();

    assert_eq!(sent_sessions(&server).await.len(), 1, "the event left");
    assert!(!keys_user(&keyed_after(&server, start).await, &bob), "Bob got the room key");

    // A later check that passes with Bob, bound again, keys him.
    room.bind_room_key_recipients(bound_to(&[&alice, &bob]));
    let rebound = requests_so_far(&server).await;
    send(&room, "rebound").await.unwrap();
    assert!(keys_user(&keyed_after(&server, rebound).await, &bob), "Bob got no key");
}

#[async_test]
async fn test_a_room_key_shared_before_the_binding_never_encrypts_the_next_event() {
    let room_id = room_id!("!portal:example.org");
    let server = MatrixMockServer::new().await;
    let (alice, bob) = alice_and_bob(&server, room_id, true).await;
    let room = alice.get_room(room_id).unwrap();

    send(&room, "before").await.unwrap();
    let before = sent_sessions(&server).await;
    let binding = bound_to(&[&alice]);
    {
        let olm = alice.olm_machine_for_testing().await;
        let olm = olm.as_ref().unwrap();
        assert!(!olm.room_key_shared_within(room_id, &before[0], &binding).await);
    }
    room.bind_room_key_recipients(binding.clone());
    let bound_at = requests_so_far(&server).await;

    send(&room, "after").await.unwrap();

    let sessions = sent_sessions(&server).await;
    assert_eq!(sessions.len(), 2);
    assert_ne!(sessions[1], sessions[0], "the session Bob holds encrypted the next event");
    let olm = alice.olm_machine_for_testing().await;
    assert!(olm.as_ref().unwrap().room_key_shared_within(room_id, &sessions[1], &binding).await);
    assert!(!keys_user(&keyed_after(&server, bound_at).await, &bob), "Bob was sent a room key");
}

#[async_test]
async fn test_a_device_a_bound_user_gains_after_the_binding_gets_no_room_key() {
    let room_id = room_id!("!portal:example.org");
    let server = MatrixMockServer::new().await;
    let (alice, bob) = alice_and_bob(&server, room_id, true).await;
    let room = alice.get_room(room_id).unwrap();
    let bob_device = bob.device_id().unwrap().to_owned();

    // The client checked Bob's one device and bound his key to it; Bob gains
    // a second device before the share.
    let mut binding = bound_to(&[&alice]);
    binding.allow_devices(user(&bob), [bob_device.clone()]);
    room.bind_room_key_recipients(binding);
    let _bob_two =
        server.set_up_new_device_for_encryption(&bob, device_id!("BOBTWO"), vec![&alice]).await;
    let start = requests_so_far(&server).await;

    send(&room, "bound").await.unwrap();

    let keyed = keyed_after(&server, start).await;
    assert!(keyed.contains(&format!("{}|{bob_device}", user(&bob))), "{keyed:?}");
    assert!(!keyed.contains(&format!("{}|BOBTWO", user(&bob))), "the new device got the key");

    // The control: bound to any of Bob's devices, the new one is keyed.
    room.bind_room_key_recipients(bound_to(&[&alice, &bob]));
    let rebound = requests_so_far(&server).await;
    send(&room, "rebound").await.unwrap();
    assert!(
        keyed_after(&server, rebound).await.contains(&format!("{}|BOBTWO", user(&bob))),
        "the setup never keys Bob's new device"
    );
}

#[async_test]
async fn test_a_device_left_out_of_the_binding_rotates_the_session_it_holds() {
    let room_id = room_id!("!portal:example.org");
    let server = MatrixMockServer::new().await;
    let (alice, bob) = alice_and_bob(&server, room_id, true).await;
    let room = alice.get_room(room_id).unwrap();

    send(&room, "before").await.unwrap();
    let mut binding = bound_to(&[&alice]);
    binding.allow_devices(user(&bob), []);
    room.bind_room_key_recipients(binding);
    let bound_at = requests_so_far(&server).await;

    send(&room, "after").await.unwrap();

    let sessions = sent_sessions(&server).await;
    assert_ne!(sessions[1], sessions[0], "the session Bob's device holds encrypted the event");
    assert!(!keys_user(&keyed_after(&server, bound_at).await, &bob));
}

/// Answers the first `/sendToDevice` only after `delay`, and notifies
/// `reached` when it arrives.
struct HeldShare {
    reached: Arc<tokio::sync::Notify>,
    delay: Duration,
}

impl Respond for HeldShare {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        self.reached.notify_one();
        ResponseTemplate::new(200).set_body_json(serde_json::json!({})).set_delay(self.delay)
    }
}

async fn hold_shares(
    server: &MatrixMockServer,
    times: u64,
    delay: Duration,
) -> Arc<tokio::sync::Notify> {
    let reached = Arc::new(tokio::sync::Notify::new());
    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/client/v3/sendToDevice/.*/.*"))
        .respond_with(HeldShare { reached: reached.clone(), delay })
        .up_to_n_times(times)
        .with_priority(1)
        .mount(server.server())
        .await;
    reached
}

#[async_test]
async fn test_a_share_under_an_earlier_binding_never_encrypts_an_event_sent_under_a_later_one() {
    let room_id = room_id!("!portal:example.org");
    let server = MatrixMockServer::new().await;
    let (alice, bob) = alice_and_bob(&server, room_id, true).await;
    let reached = hold_shares(&server, 1, Duration::from_secs(2)).await;
    let room = alice.get_room(room_id).unwrap();

    // A send checked with Bob shares a key with him; while that share is
    // being sent, a check without Bob binds the room again and sends, its
    // share joining the running one.
    room.bind_room_key_recipients(bound_to(&[&alice, &bob]));
    let first = send(&room, "with Bob");
    let second = async {
        tokio::time::timeout(Duration::from_secs(10), reached.notified())
            .await
            .expect("the first share reached the server");
        let olm = alice.olm_machine_for_testing().await;
        let held = olm
            .as_ref()
            .unwrap()
            .store()
            .get_outbound_group_session(room_id)
            .await
            .unwrap()
            .expect("the session being shared")
            .session_id()
            .to_owned();
        drop(olm);
        room.bind_room_key_recipients(bound_to(&[&alice]));
        send(&room, "without Bob").await.unwrap();
        held
    };
    let (first, held) =
        tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(first, second) })
            .await
            .expect("both sends finish");
    first.unwrap();

    let sessions = sent_sessions(&server).await;
    assert_eq!(sessions.len(), 2, "{sessions:?}");
    // Checked against the binding in place after encrypting, neither event
    // leaves under the session Bob holds: the one sent without him must
    // not, and the first, checked once the room was bound again, does not.
    assert!(
        !sessions.contains(&held),
        "an event left under the session Bob holds once he was left out: {sessions:?}"
    );
}

#[async_test]
async fn test_a_send_that_finds_no_bound_room_key_twice_sends_nothing() {
    let room_id = room_id!("!portal:example.org");
    let server = MatrixMockServer::new().await;
    let (alice, bob) = alice_and_bob(&server, room_id, true).await;
    let reached = hold_shares(&server, 2, Duration::from_secs(1)).await;
    let room = alice.get_room(room_id).unwrap();
    room.bind_room_key_recipients(bound_to(&[&alice, &bob]));
    let bound_at = requests_so_far(&server).await;

    // Each share's session is invalidated while it is being sent, so the
    // check after encrypting fails, the rotation's session fails it too, and
    // the send must stop there.
    let sending = send(&room, "never sent");
    let spoil = async {
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(10), reached.notified())
                .await
                .expect("a share reached the server");
            let olm = alice.olm_machine_for_testing().await;
            assert!(olm.as_ref().unwrap().discard_room_key(room_id).await.unwrap());
        }
    };
    let (sent, ()) =
        tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(sending, spoil) })
            .await
            .expect("the send finishes");

    assert!(matches!(sent, Err(matrix_sdk::Error::RoomKeySharedBeyondBoundRecipients)), "{sent:?}");
    let requests = server.server().received_requests().await.unwrap();
    assert!(
        !requests[bound_at..].iter().any(|request| request.url.path().contains("/send/")),
        "an event left"
    );
}
