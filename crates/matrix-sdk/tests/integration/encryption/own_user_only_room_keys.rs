//! Filow patch 3: `Room::share_room_keys_only_with_own_user`. A room key
//! another member holds never encrypts an event sent after the room is
//! marked, whether it was shared before the mark or by a share that was
//! running while the mark was set.

use std::{sync::Arc, time::Duration};

use matrix_sdk::{Client, test_utils::mocks::MatrixMockServer};
use matrix_sdk_test::{JoinedRoomBuilder, async_test, event_factory::EventFactory};
use ruma::{
    RoomId, RoomVersionId, event_id, events::room::message::RoomMessageEventContent, room_id,
};
use serde_json::Value;
use wiremock::{
    Mock, Request, Respond, ResponseTemplate,
    matchers::{method, path_regex},
};

/// Alice and Bob, both with a device each other knows, in an encrypted room.
async fn alice_and_bob_in_a_room(server: &MatrixMockServer, room_id: &RoomId) -> (Client, Client) {
    server.mock_crypto_endpoints_preset().await;
    let (alice, bob) = server.set_up_alice_and_bob_for_encryption().await;
    let alice_id = alice.user_id().unwrap().to_owned();
    let bob_id = bob.user_id().unwrap().to_owned();
    let f = EventFactory::new().room(room_id).sender(&alice_id);
    server
        .mock_get_members()
        .ok(vec![f.member(&alice_id).into_raw(), f.member(&bob_id).into_raw()])
        .mount()
        .await;
    server.mock_room_send().ok(event_id!("$sent")).mount().await;
    server
        .mock_sync()
        .ok_and_run(&alice, |builder| {
            builder.add_joined_room(
                JoinedRoomBuilder::new(room_id)
                    .add_state_event(f.create(&alice_id, RoomVersionId::V1))
                    .add_state_event(f.room_encryption())
                    .add_state_event(f.member(&alice_id))
                    .add_state_event(f.member(&bob_id)),
            );
        })
        .await;
    (alice, bob)
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

/// The users a `/sendToDevice` of a room key was addressed to, after the
/// first `skip` requests.
async fn room_key_recipients_after(server: &MatrixMockServer, skip: usize) -> Vec<String> {
    let requests = server.server().received_requests().await.unwrap();
    requests[skip..]
        .iter()
        .filter(|request| request.url.path().contains("/sendToDevice/m.room.encrypted/"))
        .flat_map(|request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            body["messages"].as_object().unwrap().keys().cloned().collect::<Vec<_>>()
        })
        .collect()
}

#[async_test]
async fn test_a_room_key_shared_before_the_mark_never_encrypts_the_next_event() {
    let room_id = room_id!("!ai:example.org");
    let server = MatrixMockServer::new().await;
    let (alice, bob) = alice_and_bob_in_a_room(&server, room_id).await;
    mount_send_to_device(&server).await;
    let room = alice.get_room(room_id).unwrap();

    room.send(RoomMessageEventContent::text_plain("before")).await.unwrap();
    let before = sent_sessions(&server).await;
    assert_eq!(before.len(), 1);
    {
        let olm = alice.olm_machine_for_testing().await;
        let olm = olm.as_ref().unwrap();
        assert!(!olm.room_key_shared_only_with_own_user(room_id, Some(&before[0])).await);
    }
    let marked_at = server.server().received_requests().await.unwrap().len();

    room.share_room_keys_only_with_own_user().await.unwrap();
    // Discarded as soon as the room is marked, before any share or send.
    {
        let olm = alice.olm_machine_for_testing().await;
        let session = olm
            .as_ref()
            .unwrap()
            .store()
            .get_outbound_group_session(room_id)
            .await
            .unwrap()
            .expect("the session Bob holds");
        assert_eq!(session.session_id(), before[0]);
        assert!(session.invalidated(), "the session Bob holds is still in use");
    }
    room.send(RoomMessageEventContent::text_plain("after")).await.unwrap();

    let sessions = sent_sessions(&server).await;
    assert_eq!(sessions.len(), 2);
    assert_ne!(sessions[1], sessions[0], "the session Bob holds encrypted the next event");
    let olm = alice.olm_machine_for_testing().await;
    let olm = olm.as_ref().unwrap();
    assert!(olm.room_key_shared_only_with_own_user(room_id, Some(&sessions[1])).await);
    let bob_id = bob.user_id().unwrap().to_string();
    assert!(
        !room_key_recipients_after(&server, marked_at).await.contains(&bob_id),
        "Bob was sent a room key after the mark"
    );
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

#[async_test]
async fn test_a_share_running_while_the_room_is_marked_never_encrypts_the_next_event() {
    let room_id = room_id!("!ai:example.org");
    let server = MatrixMockServer::new().await;
    let (alice, _bob) = alice_and_bob_in_a_room(&server, room_id).await;
    let reached = Arc::new(tokio::sync::Notify::new());
    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/client/v3/sendToDevice/.*/.*"))
        .respond_with(HeldShare { reached: reached.clone(), delay: Duration::from_secs(2) })
        .up_to_n_times(1)
        .with_priority(1)
        .mount(server.server())
        .await;
    mount_send_to_device(&server).await;
    let room = alice.get_room(room_id).unwrap();

    // A send starts before the mark and shares a key with Bob; while its
    // share is still being sent, the room is marked and another event sent.
    let unmarked = room.send(RoomMessageEventContent::text_plain("unmarked"));
    let marked = async {
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
        room.share_room_keys_only_with_own_user().await.unwrap();
        room.send(RoomMessageEventContent::text_plain("marked")).await.unwrap();
        held
    };
    let (unmarked, held) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(unmarked.into_future(), marked)
    })
    .await
    .expect("both sends finish");
    unmarked.unwrap();

    let sessions = sent_sessions(&server).await;
    assert_eq!(sessions.len(), 2, "{sessions:?}");
    assert!(
        !sessions.contains(&held),
        "an event left under the session Bob was being sent: {sessions:?}"
    );
}
