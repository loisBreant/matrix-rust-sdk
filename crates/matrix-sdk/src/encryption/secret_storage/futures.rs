// Copyright 2023 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{future::IntoFuture, pin::Pin};

use futures_core::Future;
use matrix_sdk_base::crypto::secret_storage::SecretStorageKey;
use ruma::events::{
    secret::request::SecretName, secret_storage::default_key::SecretStorageDefaultKeyEventContent,
};

use super::{Result, SecretStorage, SecretStore};

/// Future returned by [`SecretStorage::create_secret_store()`].
#[derive(Debug)]
pub struct CreateStore<'a> {
    pub(super) secret_storage: &'a SecretStorage,
    pub(super) passphrase: Option<&'a str>,
    pub(super) backup_key: Option<&'a str>,
    pub(super) export_cross_signing_keys: bool,
}

impl<'a> CreateStore<'a> {
    /// Set the passphrase for the new [`SecretStore`].
    ///
    /// See the documentation for the [`SecretStorage::create_secret_store()`]
    /// method for more info.
    pub fn with_passphrase(mut self, passphrase: &'a str) -> Self {
        self.passphrase = Some(passphrase);

        self
    }

    /// Store this backup recovery key (unpadded base64, as
    /// `m.megolm_backup.v1` holds it) in the new [`SecretStore`] instead of
    /// the one this device holds, if any.
    ///
    /// Filow patch 4: a caller moving secret storage to a new key can then
    /// store the backup key it chose without writing this device's own one
    /// first, so the new key encrypts exactly one `m.megolm_backup.v1`
    /// ciphertext and the homeserver has no other one to serve. The key is
    /// stored as given; checking it is the caller's job.
    pub fn with_backup_key(mut self, backup_key: &'a str) -> Self {
        self.backup_key = Some(backup_key);

        self
    }

    /// Store none of this device's private cross-signing keys in the new
    /// [`SecretStore`].
    ///
    /// Filow patch 4: a caller moving secret storage to a new key while the
    /// identity this device holds must not be stored under it (it is about to
    /// be replaced) writes no ciphertext of it there at all, rather than
    /// writing it and removing it afterwards, which leaves a ciphertext the
    /// homeserver can serve again.
    pub fn without_cross_signing_keys(mut self) -> Self {
        self.export_cross_signing_keys = false;

        self
    }
}

impl<'a> IntoFuture for CreateStore<'a> {
    type Output = Result<SecretStore>;
    #[cfg(target_family = "wasm")]
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + 'a>>;
    #[cfg(not(target_family = "wasm"))]
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        let Self { secret_storage, passphrase, backup_key, export_cross_signing_keys } = self;

        Box::pin(async move {
            // Prevent multiple simultaneous calls to this method.
            //
            // See the documentation for the lock in the `store_secret` method for more
            // info.
            let client_copy = secret_storage.client.to_owned();
            let _guard = client_copy.locks().open_secret_store_lock.lock().await;

            let new_key = if let Some(passphrase) = passphrase {
                SecretStorageKey::new_from_passphrase(passphrase)
            } else {
                SecretStorageKey::new()
            };

            let content = new_key.event_content().to_owned();

            secret_storage.client.account().set_account_data(content).await?;

            let store = SecretStore { client: secret_storage.client.to_owned(), key: new_key };
            if export_cross_signing_keys {
                store.export_cross_signing_keys().await?;
            }

            if let Some(backup_key) = backup_key {
                store.put_secret(SecretName::RecoveryKey, backup_key).await?;
            } else {
                store.export_backup_key().await?;
            }

            let default_key_content =
                SecretStorageDefaultKeyEventContent::new(store.key.key_id().to_owned());

            store.client.account().set_account_data(default_key_content).await?;

            Ok(store)
        })
    }
}
