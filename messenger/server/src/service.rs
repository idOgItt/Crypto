use crate::chat_manager::{ChatManager, ClientId, RoomId};
use futures::StreamExt;
use messenger_protos::{
    ChatMessage as ProtoChatMessage, ClientRequest, ClientRequestType, EncryptionAlgorithm, ErrorNotification, KeyExchangeData as ProtoKeyExchangeData, MessengerService, RoomClosedNotification,
    RoomInfo, ServerAck, ServerEventType, ServerMessage, UserStatusUpdate,
};
use num_bigint::BigUint;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

pub struct SecureMessengerService {
    chat_manager: Arc<ChatManager>,
}

impl SecureMessengerService {
    pub fn new(chat_manager: Arc<ChatManager>) -> Self {
        Self { chat_manager }
    }

    async fn send_to_client(tx: &mpsc::Sender<Result<ServerMessage, Status>>, msg: ServerMessage) {
        if let Err(e) = tx.send(Ok(msg)).await {
            log::warn!("Failed to send message to client: {}", e);
        }
    }

    async fn broadcast_to_room(&self, room_id: &RoomId, message: ServerMessage, exclude_client_id: Option<&ClientId>) {
        if let Some(room) = self.chat_manager.get_room(room_id) {
            for participant_entry in room.participants.iter() {
                let participant_id = participant_entry.key();
                let participant = participant_entry.value();
                if exclude_client_id.map_or(true, |id| id != participant_id) {
                    Self::send_to_client(&participant.tx, message.clone()).await;
                }
            }
        }
    }
}

#[tonic::async_trait]
impl MessengerService for SecureMessengerService {
    type ChatStreamStream = ReceiverStream<Result<ServerMessage, Status>>;

    async fn chat_stream(&self, request: Request<Streaming<ClientRequest>>) -> Result<Response<Self::ChatStreamStream>, Status> {
        let mut client_request_stream = request.into_inner();
        let (tx_to_client, rx_from_server) = mpsc::channel(128);

        let temp_client_id_for_setup = uuid::Uuid::new_v4().to_string();

        let manager = Arc::clone(&self.chat_manager);
        let initial_tx_clone = tx_to_client.clone();

        tokio::spawn(async move {
            let mut current_client_id: Option<ClientId> = None;

            while let Some(result) = client_request_stream.next().await {
                match result {
                    Ok(client_req) => {
                        let req_id = client_req.request_id.clone();
                        let client_id_from_req = client_req.client_id.clone();

                        if current_client_id.is_none() {
                            current_client_id = Some(client_id_from_req.clone());
                            manager.add_client(client_id_from_req.clone(), initial_tx_clone.clone());
                            log::info!("Client {} connected and registered.", client_id_from_req);
                        } else if current_client_id.as_ref() != Some(&client_id_from_req) {
                            log::warn!("Client ID mismatch in stream! Expected {:?}, got {}. Ignoring request.", current_client_id, client_id_from_req);
                            let error_msg = ServerMessage {
                                message_id: uuid::Uuid::new_v4().to_string(),
                                timestamp: chrono::Utc::now().timestamp_millis(),
                                event: Some(ServerEventType::Error(ErrorNotification {
                                    message: "Client ID mismatch in stream".to_string(),
                                    error_code: 4001,
                                })),
                            };
                            Self::send_to_client(&tx_to_client, error_msg).await;
                            continue;
                        }

                        let client_id = current_client_id.as_ref().unwrap();

                        if let Some(request_type) = client_req.request {
                            match request_type {
                                ClientRequestType::CreateRoom(create_req) => {
                                    let room = manager.create_room(messenger_protos::EncryptionAlgorithm::from_i32(create_req.algorithm).unwrap());
                                    match manager.client_join_room(client_id, &room.id) {
                                        Ok(joined_room) => {
                                            let room_info_msg = ServerMessage {
                                                message_id: uuid::Uuid::new_v4().to_string(),
                                                timestamp: chrono::Utc::now().timestamp_millis(),
                                                event: Some(ServerEventType::RoomInfo(RoomInfo {
                                                    room_id: joined_room.id.clone(),
                                                    algorithm: joined_room.algorithm.into(),
                                                    participants: vec![client_id.clone()],
                                                })),
                                            };
                                            Self::send_to_client(&tx_to_client, room_info_msg).await;
                                        }
                                        Err(e) => {
                                            let error_msg = ServerMessage { ..Default::default() };
                                            Self::send_to_client(&tx_to_client, error_msg).await;
                                        }
                                    }
                                }
                                ClientRequestType::JoinRoom(join_req) => match manager.client_join_room(client_id, &join_req.room_id) {
                                    Ok(joined_room) => {
                                        let current_participants: Vec<String> = joined_room.participants.iter().map(|p| p.key().clone()).collect();
                                        let room_info_msg = ServerMessage {
                                            message_id: uuid::Uuid::new_v4().to_string(),
                                            timestamp: chrono::Utc::now().timestamp_millis(),
                                            event: Some(ServerEventType::RoomInfo(RoomInfo {
                                                room_id: joined_room.id.clone(),
                                                algorithm: joined_room.algorithm.into(),
                                                participants: current_participants.clone(),
                                            })),
                                        };
                                        Self::send_to_client(&tx_to_client, room_info_msg).await;

                                        let user_joined_update = ServerMessage {
                                            message_id: uuid::Uuid::new_v4().to_string(),
                                            timestamp: chrono::Utc::now().timestamp_millis(),
                                            event: Some(ServerEventType::UserStatus(UserStatusUpdate {
                                                room_id: joined_room.id.clone(),
                                                client_id: client_id.clone(),
                                                joined: true,
                                            })),
                                        };
                                        if let Some(room_arc) = manager.get_room(&joined_room.id) {
                                            for participant_entry in room_arc.participants.iter() {
                                                if participant_entry.key() != client_id {
                                                    Self::send_to_client(&participant_entry.value().tx, user_joined_update.clone()).await;
                                                }
                                            }
                                        }

                                        if joined_room.participants.len() == 2 {
                                            log::info!("Room {} is full, initiating DH or waiting for keys.", joined_room.id);
                                        }
                                    }
                                    Err(e) => {
                                        let error_msg = ServerMessage {
                                            message_id: uuid::Uuid::new_v4().to_string(),
                                            timestamp: chrono::Utc::now().timestamp_millis(),
                                            event: Some(ServerEventType::Error(ErrorNotification { message: e, error_code: 0 })),
                                        };
                                        Self::send_to_client(&tx_to_client, error_msg).await;
                                    }
                                },
                                ClientRequestType::LeaveRoom(leave_req) => match manager.client_leave_room(client_id, &leave_req.room_id) {
                                    Ok(_) => {
                                        let ack = ServerMessage {
                                            message_id: uuid::Uuid::new_v4().to_string(),
                                            timestamp: chrono::Utc::now().timestamp_millis(),
                                            event: Some(ServerEventType::ServerAck(ServerAck {
                                                original_request_id: req_id,
                                                success: true,
                                                details: "Left room".into(),
                                            })),
                                        };
                                        Self::send_to_client(&tx_to_client, ack).await;

                                        let user_left_update = ServerMessage {
                                            message_id: uuid::Uuid::new_v4().to_string(),
                                            timestamp: chrono::Utc::now().timestamp_millis(),
                                            event: Some(ServerEventType::UserStatus(UserStatusUpdate {
                                                room_id: leave_req.room_id.clone(),
                                                client_id: client_id.clone(),
                                                joined: false,
                                            })),
                                        };
                                        if let Some(room_arc) = manager.get_room(&leave_req.room_id) {
                                            for participant_entry in room_arc.participants.iter() {
                                                Self::send_to_client(&participant_entry.value().tx, user_left_update.clone()).await;
                                            }
                                        }
                                    }
                                    Err(e) => {}
                                },
                                ClientRequestType::SendMessage(send_msg_req) => {
                                    let chat_msg_event = ProtoChatMessage {
                                        room_id: send_msg_req.room_id.clone(),
                                        sender_id: client_id.clone(),
                                        iv: send_msg_req.iv,
                                        encrypted_payload: send_msg_req.encrypted_payload,
                                        payload_type: send_msg_req.payload_type,
                                        filename: send_msg_req.filename,
                                        is_last_chunk: send_msg_req.is_last_chunk,
                                        chunk_sequence_number: send_msg_req.chunk_sequence_number,
                                        unique_transfer_id: send_msg_req.unique_transfer_id.clone(),
                                    };
                                    let server_msg = ServerMessage {
                                        message_id: uuid::Uuid::new_v4().to_string(),
                                        timestamp: chrono::Utc::now().timestamp_millis(),
                                        event: Some(ServerEventType::ChatMessage(chat_msg_event)),
                                    };

                                    if let Some(room) = manager.get_room(&send_msg_req.room_id) {
                                        if let Some(recipient) = room.get_other_participant(client_id) {
                                            Self::send_to_client(&recipient.tx, server_msg).await;
                                        } else {
                                            let error_msg = ServerMessage {
                                                message_id: uuid::Uuid::new_v4().to_string(),
                                                timestamp: chrono::Utc::now().timestamp_millis(),
                                                event: Some(ServerEventType::Error(ErrorNotification {
                                                    message: "No recipient in room".into(),
                                                    error_code: 0,
                                                })),
                                            };
                                            Self::send_to_client(&tx_to_client, error_msg).await;
                                        }
                                    } else {
                                        let error_msg = ServerMessage {
                                            message_id: uuid::Uuid::new_v4().to_string(),
                                            timestamp: chrono::Utc::now().timestamp_millis(),
                                            event: Some(ServerEventType::Error(ErrorNotification {
                                                message: "Room not found".into(),
                                                error_code: 0,
                                            })),
                                        };
                                        Self::send_to_client(&tx_to_client, error_msg).await;
                                    }
                                }
                                ClientRequestType::SendKeyExchange(send_key_req) => {
                                    let key_data_event = ProtoKeyExchangeData {
                                        room_id: send_key_req.room_id.clone(),
                                        from_client_id: client_id.clone(),
                                        to_client_id: "".to_string(),
                                        public_key_dh: send_key_req.public_key_dh,
                                    };
                                    let server_msg = ServerMessage {
                                        message_id: uuid::Uuid::new_v4().to_string(),
                                        timestamp: chrono::Utc::now().timestamp_millis(),
                                        event: Some(ServerEventType::KeyExchangeData(key_data_event)),
                                    };

                                    if let Some(room) = manager.get_room(&send_key_req.room_id) {
                                        if let Some(recipient) = room.get_other_participant(client_id) {
                                            Self::send_to_client(&recipient.tx, server_msg).await;
                                            log::info!("Forwarded DH key from {} to {} in room {}", client_id, recipient.id, send_key_req.room_id);
                                        } else {
                                            log::warn!("DH Key: No recipient in room {} for client {}", send_key_req.room_id, client_id);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Error receiving from client stream: {:?}", e);
                        break;
                    }
                }
            }

            if let Some(id) = current_client_id {
                log::info!("Client {} disconnected.", id);
                if let Some(client_arc) = manager.get_client(&id) {
                    if let Some(room_id) = &client_arc.current_room_id {
                        let user_left_update = ServerMessage {
                            message_id: uuid::Uuid::new_v4().to_string(),
                            timestamp: chrono::Utc::now().timestamp_millis(),
                            event: Some(ServerEventType::UserStatus(UserStatusUpdate {
                                room_id: room_id.clone(),
                                client_id: id.clone(),
                                joined: false,
                            })),
                        };
                        if let Some(room_arc_notify) = manager.get_room(room_id) {
                            for participant_entry in room_arc_notify.participants.iter() {
                                if participant_entry.key() != &id {
                                    Self::send_to_client(&participant_entry.value().tx, user_left_update.clone()).await;
                                }
                            }
                        }
                    }
                }
                manager.remove_client(&id);
            } else {
                log::warn!("Client disconnected before ID was established.");
            }
        });

        Ok(Response::new(ReceiverStream::new(rx_from_server)))
    }
}
