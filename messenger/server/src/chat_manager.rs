use dashmap::DashMap;
use dh_crypto::DhParameters; // For storing DH parameters if server defines them.
use messenger_protos::{EncryptionAlgorithm, ServerMessage};
use num_bigint::BigUint;
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

pub type ClientId = String;
pub type RoomId = String;
pub type ClientTx = mpsc::Sender<Result<ServerMessage, tonic::Status>>;

#[derive(Debug, Clone)]
pub struct Client {
    pub id: ClientId,
    pub tx: ClientTx,
    pub current_room_id: Option<RoomId>,
    pub dh_public_key: Option<BigUint>,
}

#[derive(Debug)]
pub struct Room {
    pub id: RoomId,
    pub algorithm: EncryptionAlgorithm,
    pub participants: DashMap<ClientId, Arc<Client>>, 
    // pub dh_params: Option<Arc<DhParameters>>, 
    pub expected_participants: usize,
}

impl Room {
    pub fn new(id: RoomId, algorithm: EncryptionAlgorithm, expected_participants: usize) -> Self {
        Self {
            id,
            algorithm,
            participants: DashMap::new(),
            expected_participants,
        }
    }

    pub fn is_full(&self) -> bool {
        self.participants.len() >= self.expected_participants
    }

    pub fn add_participant(&self, client: Arc<Client>) -> bool {
        if self.is_full() && !self.participants.contains_key(&client.id) {
            return false;
        }
        self.participants.insert(client.id.clone(), client);
        true
    }

    pub fn remove_participant(&self, client_id: &ClientId) -> Option<Arc<Client>> {
        self.participants.remove(client_id).map(|(_, client)| client)
    }

    pub fn get_other_participant(&self, self_id: &ClientId) -> Option<Arc<Client>> {
        self.participants.iter().find(|entry| entry.key() != self_id).map(|entry| Arc::clone(entry.value()))
    }
}

#[derive(Clone)]
pub struct ChatManager {
    rooms: Arc<DashMap<RoomId, Arc<Room>>>,
    clients: Arc<DashMap<ClientId, Arc<Client>>>,
}

impl ChatManager {
    pub fn new() -> Self {
        Self {
            rooms: Arc::new(DashMap::new()),
            clients: Arc::new(DashMap::new()),
        }
    }

    pub fn create_room(&self, algorithm: EncryptionAlgorithm) -> Arc<Room> {
        let room_id = Uuid::new_v4().to_string();
        let room = Arc::new(Room::new(room_id, algorithm, 2)); // 2 participants for a chat
        self.rooms.insert(room.id.clone(), Arc::clone(&room));
        log::info!("Room created: {} with algo {:?}", room.id, algorithm);
        room
    }

    pub fn add_client(&self, client_id: ClientId, tx: ClientTx) -> Arc<Client> {
        let client = Arc::new(Client {
            id: client_id.clone(),
            tx,
            current_room_id: None,
            dh_public_key: None,
        });
        self.clients.insert(client_id, Arc::clone(&client));
        client
    }

    pub fn get_client(&self, client_id: &ClientId) -> Option<Arc<Client>> {
        self.clients.get(client_id).map(|c| Arc::clone(c.value()))
    }

    pub fn update_client_dh_key(&self, client_id: &ClientId, dh_public_key: BigUint) {
        // BUGFIX: Removed the deadlock-causing `get_mut` wrapper.
        // The original code tried to `get` while holding a mutable reference from `get_mut`.
        if let Some(old_client_arc) = self.clients.get(client_id).map(|c| Arc::clone(c.value())) {
            let new_client_arc = Arc::new(Client {
                dh_public_key: Some(dh_public_key),
                ..(*old_client_arc).clone() // clone inner client data
            });
            self.clients.insert(client_id.clone(), new_client_arc);
        }
    }

    pub fn remove_client(&self, client_id: &ClientId) -> Option<Arc<Client>> {
        log::debug!("Attempting to remove client: {}", client_id);
        let client = self.clients.remove(client_id).map(|(_, c)| c);
        if let Some(ref removed_client) = client {
            if let Some(room_id) = &removed_client.current_room_id {
                if let Some(room) = self.rooms.get(room_id) {
                    log::debug!("Removing client {} from room {}", client_id, room_id);
                    room.remove_participant(client_id);
                    if room.participants.is_empty() {
                        log::info!("Room {} is empty, removing.", room_id);
                        self.rooms.remove(room_id);
                    }
                }
            }
        }
        client
    }

    pub fn get_room(&self, room_id: &RoomId) -> Option<Arc<Room>> {
        self.rooms.get(room_id).map(|r| Arc::clone(r.value()))
    }

    pub fn client_join_room(&self, client_id: &ClientId, room_id: &RoomId) -> Result<Arc<Room>, String> {
        let client_arc = self.get_client(client_id).ok_or_else(|| "Client not found".to_string())?;
        let room_arc = self.get_room(room_id).ok_or_else(|| format!("Room {} not found", room_id))?;

        if room_arc.is_full() && !room_arc.participants.contains_key(client_id) {
            return Err(format!("Room {} is full.", room_id));
        }

        // Update client's current room.
        if let Some(old_client_arc) = self.clients.get(client_id).map(|c| Arc::clone(c.value())) {
            let new_client_arc = Arc::new(Client {
                current_room_id: Some(room_id.clone()),
                ..(*old_client_arc).clone()
            });
            room_arc.add_participant(Arc::clone(&new_client_arc));
            self.clients.insert(client_id.clone(), new_client_arc); 
        } else {
            return Err("Failed to update client's room".to_string());
        }

        log::info!("Client {} joined room {}", client_id, room_id);
        Ok(room_arc)
    }

    pub fn client_leave_room(&self, client_id: &ClientId, room_id: &RoomId) -> Result<(), String> {
        let room = self.get_room(room_id).ok_or_else(|| "Room not found".to_string())?;
        room.remove_participant(client_id);
        log::info!("Client {} left room {}", client_id, room_id);
        
        if let Some(old_client_arc) = self.clients.get(client_id).map(|c| Arc::clone(c.value())) {
            let new_client_arc = Arc::new(Client {
                current_room_id: None,
                ..(*old_client_arc).clone()
            });
            self.clients.insert(client_id.clone(), new_client_arc);
        }

        if room.participants.is_empty() {
            log::info!("Room {} is now empty and has been removed.", room_id);
            self.rooms.remove(room_id);
        }
        Ok(())
    }
}
