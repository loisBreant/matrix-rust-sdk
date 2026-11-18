//! Filow patch 4: import secrets a caller already read and checked, and
//! create a secret store that writes each secret at most once.
//!
//! `SecretStore::import_secrets()` reads secret storage from the homeserver
//! itself. A caller that read and checked the secrets first would otherwise
//! import a second read, which the homeserver can answer with another
//! ciphertext stored under the same secret-storage key.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use assert_matches2::assert_matches;
use matrix_sdk::{
    Client,
    encryption::{secret_storage::SecretStorageError, vodozemac::Ed25519SecretKey},
    test_utils::mocks::MatrixMockServer,
};
use matrix_sdk_base::crypto::{CrossSigningKeyExport, store::types::BackupDecryptionKey};
use matrix_sdk_test::async_test;
use ruma::{DeviceId, device_id, events::secret::request::SecretName, owned_user_id};
use serde_json::{Value, json};
use wiremock::{
    Mock, Request, Respond, ResponseTemplate,
    matchers::{method, path_regex},
};

const ACCOUNT_DATA: &str = r"^/_matrix/client/.*/user/[^/]+/account_data/[^/]+$";

/// Global account data the way a homeserver keeps it, counting each read and
/// keeping every write.
#[derive(Clone, Default)]
struct AccountData(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    data: HashMap<String, Value>,
    gets: HashMap<String, usize>,
    puts: Vec<(String, Value)>,
}

impl AccountData {
    async fn mount(&self, server: &MatrixMockServer) {
        Mock::given(path_regex(ACCOUNT_DATA))
            .respond_with(self.clone())
            .mount(server.server())
            .await;
    }

    fn gets(&self, event_type: &str) -> usize {
        self.0.lock().unwrap().gets.get(event_type).copied().unwrap_or(0)
    }

    /// The writes of `event_type` after the first `skip` writes of any type.
    fn puts_after(&self, skip: usize, event_type: &str) -> Vec<Value> {
        self.0.lock().unwrap().puts[skip..]
            .iter()
            .filter(|(name, _)| name == event_type)
            .map(|(_, body)| body.clone())
            .collect()
    }

    fn put_count(&self) -> usize {
        self.0.lock().unwrap().puts.len()
    }
}

impl Respond for AccountData {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let event_type = request.url.path_segments().unwrap().next_back().unwrap().to_owned();
        let mut state = self.0.lock().unwrap();
        if request.method == wiremock::http::Method::PUT {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            state.puts.push((event_type.clone(), body.clone()));
            state.data.insert(event_type, body);
            return ResponseTemplate::new(200).set_body_json(json!({}));
        }
        *state.gets.entry(event_type.clone()).or_default() += 1;
        match state.data.get(&event_type) {
            Some(body) => ResponseTemplate::new(200).set_body_json(body),
            None => ResponseTemplate::new(404)
                .set_body_json(json!({ "errcode": "M_NOT_FOUND", "error": "not found" })),
        }
    }
}

const CROSS_SIGNING: [SecretName; 3] = [
    SecretName::CrossSigningMasterKey,
    SecretName::CrossSigningSelfSigningKey,
    SecretName::CrossSigningUserSigningKey,
];

/// A device of Alice's whose keys the homeserver has.
async fn device(server: &MatrixMockServer, device_id: &DeviceId) -> Client {
    let client = server
        .client_builder_for_crypto_end_to_end(&owned_user_id!("@alice:example.org"), device_id)
        .build()
        .await;
    server.mock_sync().ok_and_run(&client, |_| {}).await;
    client
}

/// Alice's first device, holding her identity, and the key of a secret
/// storage it exported everything to.
async fn first_device(server: &MatrixMockServer) -> (Client, String) {
    server.mock_crypto_endpoints_preset().await;
    let first = device(server, device_id!("FIRST")).await;
    first.encryption().bootstrap_cross_signing(None).await.unwrap();
    let store = first.encryption().secret_storage().create_secret_store().await.unwrap();
    (first, store.secret_storage_key())
}

/// The backup version the homeserver serves as current, under `key`.
async fn mount_backup_version(server: &MatrixMockServer, key: &BackupDecryptionKey) {
    mount_backup_version_with_priority(server, key, 5).await;
}

/// The same, taking over from a version mounted earlier when `priority` is
/// lower (wiremock answers with the mock of the lowest priority).
async fn mount_backup_version_with_priority(
    server: &MatrixMockServer,
    key: &BackupDecryptionKey,
    priority: u8,
) {
    let public_key = key.megolm_v1_public_key().to_base64();
    Mock::given(method("GET"))
        .and(path_regex(r"^/_matrix/client/.*/room_keys/version$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
            "auth_data": { "public_key": public_key, "signatures": {} },
            "count": 0,
            "etag": "0",
            "version": "1",
        })))
        .with_priority(priority)
        .mount(server.server())
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/client/.*/room_keys/keys$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "count": 0, "etag": "0" })))
        .mount(server.server())
        .await;
}

async fn read_cross_signing_keys(
    store: &matrix_sdk::encryption::secret_storage::SecretStore,
) -> CrossSigningKeyExport {
    let mut export = CrossSigningKeyExport::default();
    export.master_key = store.get_secret(SecretName::CrossSigningMasterKey).await.unwrap();
    export.self_signing_key =
        store.get_secret(SecretName::CrossSigningSelfSigningKey).await.unwrap();
    export.user_signing_key =
        store.get_secret(SecretName::CrossSigningUserSigningKey).await.unwrap();
    export
}

#[async_test]
async fn test_cross_signing_keys_are_imported_from_memory_without_another_read() {
    let server = MatrixMockServer::new().await;
    let account_data = AccountData::default();
    account_data.mount(&server).await;
    let (_first, key) = first_device(&server).await;
    let second = device(&server, device_id!("SECOND")).await;

    let store = second.encryption().secret_storage().open_secret_store(&key).await.unwrap();
    let reads = || -> Vec<usize> {
        CROSS_SIGNING.iter().map(|name| account_data.gets(name.as_str())).collect()
    };
    // The first device's writes read each secret too (to merge).
    let before = reads();
    let before_backup = account_data.gets(SecretName::RecoveryKey.as_str());
    let export = read_cross_signing_keys(&store).await;
    assert!(export.master_key.is_some() && export.self_signing_key.is_some());
    assert!(export.user_signing_key.is_some());
    let read_once: Vec<_> = before.iter().map(|count| count + 1).collect();
    assert_eq!(reads(), read_once);

    let status = store.import_cross_signing_keys(export).await.unwrap();

    assert!(status.is_complete(), "every key of the published identity is imported");
    assert!(second.encryption().cross_signing_status().await.unwrap().is_complete());
    let own = second.encryption().get_own_device().await.unwrap().unwrap();
    assert!(own.is_cross_signed_by_owner(), "the device is signed with the imported key");
    assert_eq!(reads(), read_once, "the import read secret storage again");
    assert_eq!(account_data.gets(SecretName::RecoveryKey.as_str()), before_backup);
}

#[async_test]
async fn test_cross_signing_keys_of_another_identity_are_not_imported() {
    let server = MatrixMockServer::new().await;
    let account_data = AccountData::default();
    account_data.mount(&server).await;
    let (_first, key) = first_device(&server).await;
    let second = device(&server, device_id!("SECOND")).await;
    let store = second.encryption().secret_storage().open_secret_store(&key).await.unwrap();
    let mut export = read_cross_signing_keys(&store).await;
    export.master_key = Some(Ed25519SecretKey::new().to_base64());

    let result = store.import_cross_signing_keys(export).await;

    assert_matches!(
        result,
        Err(SecretStorageError::ImportError { name: SecretName::CrossSigningMasterKey, .. })
    );
    let status = second.encryption().cross_signing_status().await.unwrap();
    assert!(!status.has_master && !status.has_self_signing && !status.has_user_signing);
    let own = second.encryption().get_own_device().await.unwrap().unwrap();
    assert!(!own.is_cross_signed_by_owner());
}

#[async_test]
async fn test_a_malformed_cross_signing_key_is_not_imported() {
    let server = MatrixMockServer::new().await;
    let account_data = AccountData::default();
    account_data.mount(&server).await;
    let (_first, key) = first_device(&server).await;
    let second = device(&server, device_id!("SECOND")).await;
    let store = second.encryption().secret_storage().open_secret_store(&key).await.unwrap();
    let mut export = read_cross_signing_keys(&store).await;
    export.self_signing_key = Some("not a key".to_owned());

    let result = store.import_cross_signing_keys(export).await;

    assert_matches!(
        result,
        Err(SecretStorageError::ImportError { name: SecretName::CrossSigningSelfSigningKey, .. })
    );
    let status = second.encryption().cross_signing_status().await.unwrap();
    assert!(!status.has_master && !status.has_self_signing && !status.has_user_signing);
}

#[async_test]
async fn test_the_backup_key_is_imported_from_memory_only_when_current() {
    let server = MatrixMockServer::new().await;
    let account_data = AccountData::default();
    account_data.mount(&server).await;
    let (_first, key) = first_device(&server).await;
    let current = BackupDecryptionKey::new();
    mount_backup_version(&server, &current).await;
    let second = device(&server, device_id!("SECOND")).await;
    let store = second.encryption().secret_storage().open_secret_store(&key).await.unwrap();

    let backup_reads = account_data.gets(SecretName::RecoveryKey.as_str());
    let retired = BackupDecryptionKey::new().to_base64();
    assert_matches!(
        store.import_backup_key(&retired).await,
        Err(SecretStorageError::InconsistentBackupDecryptionKey)
    );
    assert!(!second.encryption().backups().are_enabled().await);

    store.import_backup_key(&current.to_base64()).await.unwrap();

    assert!(second.encryption().backups().are_enabled().await);
    assert_eq!(
        account_data.gets(SecretName::RecoveryKey.as_str()),
        backup_reads,
        "the import read the backup key from secret storage"
    );
}

#[async_test]
async fn test_a_malformed_backup_key_is_not_imported() {
    let server = MatrixMockServer::new().await;
    let account_data = AccountData::default();
    account_data.mount(&server).await;
    let (_first, key) = first_device(&server).await;
    mount_backup_version(&server, &BackupDecryptionKey::new()).await;
    let second = device(&server, device_id!("SECOND")).await;
    let store = second.encryption().secret_storage().open_secret_store(&key).await.unwrap();

    assert_matches!(
        store.import_backup_key("not a key").await,
        Err(SecretStorageError::ImportError { name: SecretName::RecoveryKey, .. })
    );
    assert!(!second.encryption().backups().are_enabled().await);
}

/// The secret `body` (an `m.secret_storage` event content) holds, opened
/// with the secret store's key.
async fn stored_secret(client: &Client, key: &str, name: SecretName) -> Option<String> {
    let store = client.encryption().secret_storage().open_secret_store(key).await.unwrap();
    store.get_secret(name).await.unwrap()
}

/// Alice's first device, also holding the current backup's key.
async fn first_device_with_backup(server: &MatrixMockServer) -> (Client, BackupDecryptionKey) {
    let (first, key) = first_device(server).await;
    let backup = BackupDecryptionKey::new();
    mount_backup_version(server, &backup).await;
    let store = first.encryption().secret_storage().open_secret_store(&key).await.unwrap();
    store.import_backup_key(&backup.to_base64()).await.unwrap();
    assert!(first.encryption().backups().are_enabled().await);
    (first, backup)
}

#[async_test]
async fn test_a_new_store_holds_the_chosen_backup_key_and_no_identity() {
    let server = MatrixMockServer::new().await;
    let account_data = AccountData::default();
    account_data.mount(&server).await;
    let (first, _own_backup) = first_device_with_backup(&server).await;
    let chosen = BackupDecryptionKey::new().to_base64();
    let before = account_data.put_count();

    let store = first
        .encryption()
        .secret_storage()
        .create_secret_store()
        .with_backup_key(&chosen)
        .without_cross_signing_keys()
        .await
        .unwrap();

    for name in CROSS_SIGNING {
        assert!(account_data.puts_after(before, name.as_str()).is_empty(), "{name} was written");
    }
    assert_eq!(account_data.puts_after(before, SecretName::RecoveryKey.as_str()).len(), 1);
    let key = store.secret_storage_key();
    assert_eq!(stored_secret(&first, &key, SecretName::RecoveryKey).await, Some(chosen));
    // Only the new key's ciphertext: no other key's copy came along.
    let stored = &account_data.puts_after(before, SecretName::RecoveryKey.as_str())[0];
    assert_eq!(stored["encrypted"].as_object().unwrap().len(), 1);
}

#[async_test]
async fn test_a_new_store_with_a_chosen_backup_key_still_holds_the_identity() {
    let server = MatrixMockServer::new().await;
    let account_data = AccountData::default();
    account_data.mount(&server).await;
    let (first, _own_backup) = first_device_with_backup(&server).await;
    let chosen = BackupDecryptionKey::new().to_base64();
    let before = account_data.put_count();

    let store = first
        .encryption()
        .secret_storage()
        .create_secret_store()
        .with_backup_key(&chosen)
        .await
        .unwrap();

    for name in CROSS_SIGNING {
        assert_eq!(account_data.puts_after(before, name.as_str()).len(), 1, "{name}");
    }
    assert_eq!(account_data.puts_after(before, SecretName::RecoveryKey.as_str()).len(), 1);
    let key = store.secret_storage_key();
    assert_eq!(stored_secret(&first, &key, SecretName::RecoveryKey).await, Some(chosen));
}

#[async_test]
async fn test_a_new_store_without_options_still_exports_everything_the_device_holds() {
    let server = MatrixMockServer::new().await;
    let account_data = AccountData::default();
    account_data.mount(&server).await;
    let (first, own_backup) = first_device_with_backup(&server).await;
    let before = account_data.put_count();

    let store = first.encryption().secret_storage().create_secret_store().await.unwrap();

    for name in CROSS_SIGNING {
        assert_eq!(account_data.puts_after(before, name.as_str()).len(), 1, "{name}");
    }
    let key = store.secret_storage_key();
    assert_eq!(
        stored_secret(&first, &key, SecretName::RecoveryKey).await,
        Some(own_backup.to_base64())
    );
}

#[async_test]
async fn test_exporting_the_identity_leaves_the_backup_key_out() {
    let server = MatrixMockServer::new().await;
    let account_data = AccountData::default();
    account_data.mount(&server).await;
    let (first, own_backup) = first_device_with_backup(&server).await;
    let store = first.encryption().secret_storage().create_secret_store().await.unwrap();
    let before = account_data.put_count();

    store.export_cross_signing_keys().await.unwrap();

    for name in CROSS_SIGNING {
        assert_eq!(account_data.puts_after(before, name.as_str()).len(), 1, "{name}");
    }
    assert!(account_data.puts_after(before, SecretName::RecoveryKey.as_str()).is_empty());

    // export_secrets() itself is unchanged: both.
    let before = account_data.put_count();
    store.export_secrets().await.unwrap();
    for name in CROSS_SIGNING {
        assert_eq!(account_data.puts_after(before, name.as_str()).len(), 1, "{name}");
    }
    let backup = account_data.puts_after(before, SecretName::RecoveryKey.as_str());
    assert_eq!(backup.len(), 1);
    let key = store.secret_storage_key();
    assert_eq!(
        stored_secret(&first, &key, SecretName::RecoveryKey).await,
        Some(own_backup.to_base64())
    );
}

/// The backup key this device stores, as the public half.
async fn stored_backup_key(client: &Client) -> Option<String> {
    let olm = client.olm_machine_for_testing().await;
    let keys = olm.as_ref().unwrap().backup_machine().get_backup_keys().await.unwrap();
    keys.decryption_key.map(|key| key.megolm_v1_public_key().to_base64())
}

// The homeserver labels a new backup key with the version a device already
// backs up to: the device takes up the key it was given, and does not keep
// encrypting room keys to its old one because the label did not change.
#[async_test]
async fn test_a_backup_key_given_replaces_one_enabled_under_the_same_version_label() {
    let server = MatrixMockServer::new().await;
    let account_data = AccountData::default();
    account_data.mount(&server).await;
    let (first, old) = first_device_with_backup(&server).await;
    let store = first.encryption().secret_storage().create_secret_store().await.unwrap();
    let new = BackupDecryptionKey::new();
    mount_backup_version_with_priority(&server, &new, 1).await;

    // The old key is not the one the homeserver now serves for "1".
    assert_matches!(
        store.import_backup_key(&old.to_base64()).await,
        Err(SecretStorageError::InconsistentBackupDecryptionKey)
    );

    store.import_backup_key(&new.to_base64()).await.unwrap();

    assert!(first.encryption().backups().are_enabled().await);
    assert_eq!(
        stored_backup_key(&first).await,
        Some(new.megolm_v1_public_key().to_base64()),
        "kept the old key under the same version label"
    );
}

// The same key for the same version changes nothing.
#[async_test]
async fn test_the_backup_key_already_enabled_is_kept() {
    let server = MatrixMockServer::new().await;
    let account_data = AccountData::default();
    account_data.mount(&server).await;
    let (first, own) = first_device_with_backup(&server).await;
    let store = first.encryption().secret_storage().create_secret_store().await.unwrap();

    store.import_backup_key(&own.to_base64()).await.unwrap();

    assert!(first.encryption().backups().are_enabled().await);
    assert_eq!(stored_backup_key(&first).await, Some(own.megolm_v1_public_key().to_base64()));
}

#[async_test]
async fn test_the_stored_backup_public_key_is_the_one_imported() {
    let server = MatrixMockServer::new().await;
    let account_data = AccountData::default();
    account_data.mount(&server).await;
    let (first, key) = first_device(&server).await;
    assert_eq!(first.encryption().backups().stored_backup_public_key().await.unwrap(), None);
    let backup = BackupDecryptionKey::new();
    mount_backup_version(&server, &backup).await;
    let store = first.encryption().secret_storage().open_secret_store(&key).await.unwrap();

    store.import_backup_key(&backup.to_base64()).await.unwrap();

    assert_eq!(
        first.encryption().backups().stored_backup_public_key().await.unwrap(),
        Some(backup.megolm_v1_public_key().to_base64())
    );
}
