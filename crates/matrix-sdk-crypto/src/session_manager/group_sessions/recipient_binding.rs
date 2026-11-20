// Copyright 2026 The Matrix.org Foundation C.I.C.
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

//! Filow patch 7 (`FILOW.md`): the users, and optionally the devices, a
//! room key may go to, as a client judged them before a send.

use std::collections::{BTreeMap, BTreeSet};

use ruma::{DeviceId, OwnedDeviceId, OwnedUserId, UserId};

/// The users, and for some of them the devices, a room's key may be shared
/// with (Filow patch 7, `FILOW.md`).
///
/// A client checks a room's members before it sends, then binds the room's
/// key to the members it checked: a member the room gains after that check
/// gets no key, nor a device a user gains when the binding names that user's
/// devices. The share strategy still picks among what the binding permits,
/// and a session someone outside it holds is rotated, as for a member who
/// left.
///
/// An empty binding permits no one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoomKeyRecipientBinding {
    /// Each permitted user, with `None` for any of their devices the share
    /// strategy picks, or the only devices that may get the key.
    users: BTreeMap<OwnedUserId, Option<BTreeSet<OwnedDeviceId>>>,
}

impl RoomKeyRecipientBinding {
    /// A binding that permits no one yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Permits `user_id`'s devices, those the share strategy picks. Replaces
    /// a device list given for `user_id` before.
    pub fn allow_user(&mut self, user_id: OwnedUserId) -> &mut Self {
        self.users.insert(user_id, None);
        self
    }

    /// Permits only these devices of `user_id`, and among them only those
    /// the share strategy picks. Replaces what was given for `user_id`
    /// before; an empty list permits none of its devices.
    pub fn allow_devices(
        &mut self,
        user_id: OwnedUserId,
        device_ids: impl IntoIterator<Item = OwnedDeviceId>,
    ) -> &mut Self {
        self.users.insert(user_id, Some(device_ids.into_iter().collect()));
        self
    }

    /// Whether any device of `user_id` may get the key.
    pub fn permits_user(&self, user_id: &UserId) -> bool {
        self.users
            .get(user_id)
            .is_some_and(|devices| devices.as_ref().is_none_or(|d| !d.is_empty()))
    }

    /// Whether `user_id`'s device `device_id` may get the key.
    pub fn permits_device(&self, user_id: &UserId, device_id: &DeviceId) -> bool {
        match self.users.get(user_id) {
            None => false,
            Some(None) => true,
            Some(Some(devices)) => devices.contains(device_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use ruma::{device_id, owned_device_id, owned_user_id, user_id};

    use super::RoomKeyRecipientBinding;

    #[test]
    fn test_binding_permits_only_what_it_names() {
        let mut binding = RoomKeyRecipientBinding::new();
        let alice = user_id!("@alice:example.org");
        let bob = user_id!("@bob:example.org");
        let carol = user_id!("@carol:example.org");
        assert!(!binding.permits_user(alice));
        assert!(!binding.permits_device(alice, device_id!("A")));

        binding
            .allow_user(owned_user_id!("@alice:example.org"))
            .allow_devices(owned_user_id!("@bob:example.org"), [owned_device_id!("B1")])
            .allow_devices(owned_user_id!("@carol:example.org"), []);

        assert!(binding.permits_user(alice));
        assert!(binding.permits_device(alice, device_id!("ANY")));
        assert!(binding.permits_user(bob));
        assert!(binding.permits_device(bob, device_id!("B1")));
        assert!(!binding.permits_device(bob, device_id!("B2")));
        // A user whose device list is empty gets nothing.
        assert!(!binding.permits_user(carol));
        assert!(!binding.permits_device(carol, device_id!("C1")));
        assert!(!binding.permits_user(user_id!("@dave:example.org")));

        // A later call for the same user replaces the earlier one.
        binding.allow_user(owned_user_id!("@bob:example.org"));
        assert!(binding.permits_device(bob, device_id!("B2")));
        binding.allow_devices(owned_user_id!("@alice:example.org"), [owned_device_id!("A1")]);
        assert!(!binding.permits_device(alice, device_id!("ANY")));
    }
}
