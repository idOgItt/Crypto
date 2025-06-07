
use rand::rngs::OsRng;
use rand::Rng;
use uuid::Uuid;

use std::collections::BTreeMap;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::crypto::{create_cipher_box, encrypt_data};
use crate::state::{DecryptedMessageDisplay, FileInfoDisplay, GuiUpdate, RoomState};
use crate::{ui::is_image_filename, SecureMessengerEguiApp};
use messenger_protos::{ClientRequest, ClientRequestType, PayloadType as ProtoPayloadType, SendMessageRequest};

const CHUNK_SIZE: usize = 1024 * 1024;

pub struct MessageSender;

impl MessageSender {
    pub fn send_message(app: &mut SecureMessengerEguiApp, room_state: &RoomState) {
        let text_to_send = app.message_input_chat.trim().to_string();
        app.message_input_chat.clear();
        let file_path_to_send = app.selected_file_path.take();

        if text_to_send.is_empty() && file_path_to_send.is_none() {
            return;
        }


        if let Some(file_path) = file_path_to_send {
            Self::send_file(app, room_state, file_path);
        } else {
            Self::send_text_message(app, room_state, text_to_send);
        }
    }

    fn send_text_message(app: &mut SecureMessengerEguiApp, room_state: &RoomState, text: String) {
        let key = match app.get_crypto_state(&room_state.id).and_then(|cs| cs.shared_secret_key_gui.as_ref()) {
            Some(k) => k.clone(),
            None => {
                /* error handling */
                return;
            }
        };

        let to_network_tx = app.to_network_tx.as_ref().unwrap().clone();
        let gui_update_tx = app.gui_update_tx.clone();
        let client_id = app.client_id.clone();
        let room_id = room_state.id.clone();
        let algo = room_state.algorithm;

        app.tokio_rt.spawn(async move {
            let mut iv = vec![0u8; 16];
            OsRng.fill(&mut iv[..]);

            let cipher_box = match create_cipher_box(algo, &key) {
                Ok(cb) => cb,
                Err(e) => {
                    gui_update_tx.send(GuiUpdate::LocalError(e)).await.ok();
                    return;
                }
            };

            let encrypted_data = match encrypt_data(cipher_box, text.as_bytes().to_vec(), iv.clone()).await {
                Ok(d) => d,
                Err(e) => {
                    gui_update_tx.send(GuiUpdate::LocalError(e)).await.ok();
                    return;
                }
            };

            let transfer_id = Uuid::new_v4().to_string();

            let send_req = SendMessageRequest {
                unique_transfer_id: transfer_id.clone(),
                room_id: room_id.clone(),
                iv: iv.clone(),
                encrypted_payload: encrypted_data,
                payload_type: ProtoPayloadType::Text as i32,
                filename: String::new(),
                is_last_chunk: true,
                chunk_sequence_number: 0,
            };

            let client_req = ClientRequest {
                request_id: Uuid::new_v4().to_string(),
                client_id: client_id.clone(),
                timestamp: chrono::Utc::now().timestamp_millis(),
                request: Some(ClientRequestType::SendMessage(send_req)),
            };

            let display_msg = DecryptedMessageDisplay {
                unique_id: transfer_id, 
                db_id: None,
                room_id: room_id.clone(),
                sender_id: client_id.clone(),
                text_content: Some(text),
                file_info: None,
                timestamp: chrono::Utc::now(),
                is_outgoing: true,
                iv_hex: Some(hex::encode(&iv)),
            };

            gui_update_tx.send(GuiUpdate::NewMessageDecrypted(display_msg)).await.ok();
            to_network_tx.send(client_req).await.map_err(|e| format!("Failed to send message: {}", e)).ok();
        });
    }

    fn send_file(app: &mut SecureMessengerEguiApp, room_state: &RoomState, file_path: std::path::PathBuf) {
        let key = match app.get_crypto_state(&room_state.id).and_then(|cs| cs.shared_secret_key_gui.as_ref()) {
            Some(k) => k.clone(),
            None => {
                /* error handling */
                return;
            }
        };

        let transfer_id = Uuid::new_v4().to_string();
        let transfer_id_clone = transfer_id.clone();
        let filename = file_path.file_name().unwrap_or_default().to_string_lossy().into_owned();

        let optimistic_msg = DecryptedMessageDisplay {
            unique_id: Uuid::new_v4().to_string(),
            db_id: None,
            room_id: room_state.id.clone(),
            sender_id: app.client_id.clone(),
            text_content: None,
            file_info: Some(FileInfoDisplay {
                name: filename.clone(),
                path_on_disk: None,
                data_preview_texture: None,
                pending_image_data: None,
                decrypted_data: None,
                transfer_id: transfer_id.clone(),
                transfer_progress: 0.0,
                is_download: false,
                received_chunks: BTreeMap::new(),
                transfer_cancelled: false,
            }),
            timestamp: chrono::Utc::now(),
            is_outgoing: true,
            iv_hex: None,
        };

        let gui_tx_clone = app.gui_update_tx.clone();
        app.tokio_rt.spawn(async move {
            gui_tx_clone.send(GuiUpdate::NewMessageDecrypted(optimistic_msg)).await.ok();
        });

        let to_network_tx_clone = app.to_network_tx.as_ref().unwrap().clone();
        let client_id_clone = app.client_id.clone();
        let room_id_clone = room_state.id.clone();
        let algo = room_state.algorithm;
        let gui_tx_clone = app.gui_update_tx.clone();

        let transfer_task = app.tokio_rt.spawn(async move {
            let mut file = match File::open(&file_path).await {
                Ok(f) => f,
                Err(e) => {
                    gui_tx_clone.send(GuiUpdate::LocalError(format!("Failed to open file: {}", e))).await.ok();
                    return;
                }
            };
            let total_size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
            let mut bytes_sent = 0u64;
            let mut chunk_sequence_number = 0;
            let payload_type = if is_image_filename(&filename) { ProtoPayloadType::Image } else { ProtoPayloadType::File };

            loop {
                let mut chunk_buf = vec![0; CHUNK_SIZE];
                let bytes_read = match file.read(&mut chunk_buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        gui_tx_clone.send(GuiUpdate::LocalError(format!("File read error: {}", e))).await.ok();
                        break;
                    }
                };
                chunk_buf.truncate(bytes_read);

                let mut iv = vec![0u8; 16];
                OsRng.fill(&mut iv[..]);
                let cipher_box = create_cipher_box(algo, &key).unwrap();
                let encrypted_chunk = match encrypt_data(cipher_box, chunk_buf, iv.clone()).await {
                    Ok(d) => d,
                    Err(e) => {
                        gui_tx_clone.send(GuiUpdate::LocalError(format!("Encryption error: {}", e))).await.ok();
                        break;
                    }
                };

                bytes_sent += bytes_read as u64;
                let is_last_chunk = bytes_sent >= total_size;

                let send_req = SendMessageRequest {
                    unique_transfer_id: transfer_id.clone(),
                    room_id: room_id_clone.clone(),
                    iv,
                    encrypted_payload: encrypted_chunk,
                    payload_type: payload_type as i32,
                    filename: filename.clone(),
                    is_last_chunk,
                    chunk_sequence_number,
                };

                let client_req = ClientRequest {
                    request_id: Uuid::new_v4().to_string(),
                    client_id: client_id_clone.clone(),
                    timestamp: chrono::Utc::now().timestamp_millis(),
                    request: Some(ClientRequestType::SendMessage(send_req)),
                };

                if to_network_tx_clone.send(client_req).await.is_err() {
                    gui_tx_clone.send(GuiUpdate::LocalError("Network channel closed.".to_string())).await.ok();
                    break;
                }

                chunk_sequence_number += 1;
                let progress = if total_size > 0 { bytes_sent as f32 / total_size as f32 } else { 1.0 };
                gui_tx_clone
                    .send(GuiUpdate::FileTransferProgress {
                        transfer_id: transfer_id.clone(),
                        progress,
                    })
                    .await
                    .ok();

                if is_last_chunk {
                    break;
                }
            }
            gui_tx_clone.send(GuiUpdate::FileTransferFinished { transfer_id: transfer_id.clone() }).await.ok();
        });

        app.active_transfers.insert(transfer_id_clone, transfer_task.abort_handle());
    }
}
