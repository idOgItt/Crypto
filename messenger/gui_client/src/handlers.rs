use eframe::egui;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::crypto::{compute_shared_secret, create_cipher_box, decrypt_data, generate_dh_keypair, hash_shared_key};
use crate::state::DecryptedMessageDisplay;
use crate::state::FileInfoDisplay;
use crate::state::PendingImageData;
use crate::state::{CurrentView, GuiUpdate, RoomState};
use crate::ui::is_image_filename;
use crate::{db, SecureMessengerEguiApp};
use messenger_protos::{ClientRequest, ClientRequestType, EncryptionAlgorithm as ProtoAlgorithm, SendKeyExchangeData, ServerEventType};

pub struct UpdateHandler;

impl UpdateHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn handle_update(&self, app: &mut SecureMessengerEguiApp, ctx: &egui::Context, update: GuiUpdate) {
        match update {
            GuiUpdate::ConnectionAttemptResult(result) => {
                self.handle_connection_result(app, result);
            }
            GuiUpdate::ServerMessageReceived(server_msg) => {
                self.handle_server_message(app, ctx, server_msg);
            }
            GuiUpdate::GrpcStreamClosed(reason_opt) => {
                self.handle_stream_closed(app, reason_opt);
            }
            GuiUpdate::NewMessageDecrypted(new_msg) => {
                self.handle_new_message(app, ctx, new_msg);
            }
            GuiUpdate::SharedSecretEstablished { room_id, key_hash } => {
                self.handle_shared_secret_established(app, room_id, key_hash);
            }
            GuiUpdate::LocalError(e) | GuiUpdate::StatusInfo(e) => {
                self.handle_status_update(app, e);
            }
            GuiUpdate::ChatHistoryLoaded { room_id, messages } => {
                self.handle_chat_history_loaded(app, room_id, messages);
            }
            GuiUpdate::FileSelectedForSending(path) => {
                app.selected_file_path = Some(path.clone());
                app.file_op_status = format!("Selected file: {}", path.file_name().unwrap_or_default().to_string_lossy());
            }
            GuiUpdate::UserInitiatedLeaveRoom(room_id) => {
                self.handle_user_leave_room(app, room_id);
            }
            GuiUpdate::FileSaveCompleted { message_unique_id, saved_path } => {
                self.handle_file_save_completed(app, ctx, message_unique_id, saved_path);
            }
            GuiUpdate::FileTransferProgress { transfer_id, progress } => {
                self.handle_file_transfer_progress(app, transfer_id, progress);
            }
            GuiUpdate::FileTransferFinished { transfer_id } => {
                self.handle_file_transfer_finished(app, transfer_id);
            }
            GuiUpdate::FileTransferCancelled { transfer_id } => {
                self.handle_file_transfer_cancelled(app, transfer_id);
            }
            GuiUpdate::FileChunkDecrypted {
                transfer_id,
                sequence_number,
                data,
                is_last,
            } => {
                self.handle_file_chunk_decrypted(app, ctx, transfer_id, sequence_number, data, is_last);
            }
        }
    }

    fn handle_file_transfer_progress(&self, app: &mut SecureMessengerEguiApp, transfer_id: String, progress: f32) {
        for room in app.active_rooms.values_mut() {
            if let Some(msg) = room.messages.iter_mut().find(|m| m.file_info.as_ref().map_or(false, |fi| fi.transfer_id == transfer_id)) {
                if let Some(fi) = msg.file_info.as_mut() {
                    fi.transfer_progress = progress;
                }
                return;
            }
        }
    }

    fn handle_file_transfer_finished(&self, app: &mut SecureMessengerEguiApp, transfer_id: String) {
        app.active_transfers.remove(&transfer_id);
        for room in app.active_rooms.values_mut() {
            if let Some(msg) = room.messages.iter_mut().find(|m| m.file_info.as_ref().map_or(false, |fi| fi.transfer_id == transfer_id)) {
                if let Some(fi) = msg.file_info.as_mut() {
                    fi.transfer_progress = 1.0;
                }
                return;
            }
        }
    }

    fn handle_file_transfer_cancelled(&self, app: &mut SecureMessengerEguiApp, transfer_id: String) {
        app.active_transfers.remove(&transfer_id);
        for room in app.active_rooms.values_mut() {
            if let Some(msg) = room.messages.iter_mut().find(|m| m.file_info.as_ref().map_or(false, |fi| fi.transfer_id == transfer_id)) {
                if let Some(fi) = msg.file_info.as_mut() {
                    fi.transfer_cancelled = true;
                }
                return;
            }
        }
    }

    fn handle_connection_result(&self, app: &mut SecureMessengerEguiApp, result: Result<(), String>) {
        match result {
            Ok(_) => {
                app.is_connected = true;
                app.connection_status = "Connection process initiated. Waiting for server stream...".to_string();
                app.current_view = CurrentView::Lobby;
            }
            Err(e) => {
                app.is_connected = false;
                app.connection_status = format!("Connection Failed: {}", e);
            }
        }
    }

    fn handle_server_message(&self, app: &mut SecureMessengerEguiApp, _ctx: &egui::Context, server_msg: messenger_protos::ServerMessage) {
        log::debug!("GUI received server message: {:?}", server_msg);

        if let Some(event) = server_msg.event {
            match event {
                ServerEventType::RoomInfo(info) => {
                    self.handle_room_info(app, info);
                }
                ServerEventType::UserStatus(user_update) => {
                    self.handle_user_status(app, user_update);
                }
                ServerEventType::ChatMessage(chat_msg_proto) => {
                    self.handle_chat_message(app, chat_msg_proto, server_msg.timestamp);
                }
                ServerEventType::KeyExchangeData(key_data_proto) => {
                    self.handle_key_exchange_data(app, key_data_proto);
                }
                ServerEventType::RoomClosed(closed_info) => {
                    self.handle_room_closed(app, closed_info);
                }
                ServerEventType::Error(err_notification) => {
                    self.handle_server_error(app, err_notification);
                }
                _ => {}
            }
        }
    }

    fn handle_room_info(&self, app: &mut SecureMessengerEguiApp, info: messenger_protos::RoomInfo) {
        app.status_message_lobby = format!("Joined room: {}", info.room_id);

        let new_room_state = RoomState {
            id: info.room_id.clone(),
            algorithm: ProtoAlgorithm::try_from(info.algorithm).unwrap_or(ProtoAlgorithm::UnknownAlgorithm),
            participants: info.participants.clone(),
            messages: Vec::new(),
            is_dh_complete: false,
            visual_key_hash: None,
        };

        app.active_rooms.insert(info.room_id.clone(), new_room_state);

        app.switch_to_room(info.room_id.clone());

        app.get_crypto_state_mut(&info.room_id);

        self.load_chat_history(app, info.room_id.clone());

        if info.participants.len() == 2 {
            self.initiate_dh_key_exchange(app, info.room_id);
        }
    }

    fn handle_user_status(&self, app: &mut SecureMessengerEguiApp, user_update: messenger_protos::UserStatusUpdate) {
        let mut room_id_for_dh_init: Option<String> = None;
        let mut trigger_dh_reset = false;

        if let Some(room) = app.active_rooms.get_mut(&user_update.room_id) {
            let current_client_id = user_update.client_id.clone();

            if user_update.joined {
                if !room.participants.contains(&current_client_id) {
                    room.participants.push(current_client_id.clone());
                }
                if room.participants.len() == 2 && current_client_id != app.client_id {
                    room_id_for_dh_init = Some(room.id.clone());
                }
            } else {
                room.participants.retain(|id| id != &current_client_id);
                if room.participants.len() < 2 {
                    room.is_dh_complete = false;
                    trigger_dh_reset = true;
                }
            }

            app.status_message_lobby = format!("User {} {} room {}", current_client_id, if user_update.joined { "joined" } else { "left" }, user_update.room_id);
        }

        if let Some(room_id) = room_id_for_dh_init {
            self.initiate_dh_key_exchange(app, room_id);
        }

        if trigger_dh_reset {
            if let Some(crypto_state) = app.room_crypto_states.get_mut(&user_update.room_id) {
                crypto_state.reset();
            }
            let gui_tx_clone = app.gui_update_tx.clone();
            app.tokio_rt.spawn(async move {
                gui_tx_clone.send(GuiUpdate::StatusInfo("Chat is no longer end-to-end encrypted.".to_string())).await.ok();
            });
        }
    }

    fn handle_chat_message(&self, app: &mut SecureMessengerEguiApp, chat_msg_proto: messenger_protos::ChatMessage, server_timestamp: i64) {
        let room_id = chat_msg_proto.room_id.clone();
        if room_id.is_empty() {
            return;
        }

        if chat_msg_proto.payload_type != messenger_protos::PayloadType::Text as i32 {
            let transfer_id = chat_msg_proto.unique_transfer_id.clone();


            {
                let room = match app.active_rooms.get_mut(&room_id) {
                    Some(r) => r,
                    None => {
                        log::warn!("Received chunk for inactive room '{}'. Discarding.", room_id);
                        return;
                    }
                };

                let msg_exists = room.messages.iter().any(|m| m.file_info.as_ref().map_or(false, |fi| fi.transfer_id == transfer_id));
                if !msg_exists {
                    let new_msg = DecryptedMessageDisplay {
                        unique_id: Uuid::new_v4().to_string(),
                        db_id: None,
                        room_id: room_id.clone(),
                        sender_id: chat_msg_proto.sender_id.clone(),
                        text_content: None,
                        file_info: Some(FileInfoDisplay {
                            name: chat_msg_proto.filename.clone(),
                            path_on_disk: None,
                            data_preview_texture: None,
                            pending_image_data: None,
                            decrypted_data: None,
                            transfer_id: transfer_id.clone(),
                            transfer_progress: 0.0,
                            is_download: true,
                            received_chunks: BTreeMap::new(),
                            transfer_cancelled: false,
                        }),
                        timestamp: chrono::DateTime::from_timestamp(server_timestamp / 1000, 0).unwrap_or_else(|| chrono::Utc::now()),
                        is_outgoing: false,
                        iv_hex: None,
                    };
                    room.messages.push(new_msg);
                }
            } 

            let decryption_info = if let Some(room) = app.active_rooms.get(&room_id) {
                app.get_crypto_state(&room_id).and_then(|cs| cs.shared_secret_key_gui.as_ref()).map(|key| (room.algorithm, key.clone()))
            } else {
                None
            };

            if let Some((algorithm, key)) = decryption_info {
                let gui_tx = app.gui_update_tx.clone();
                app.tokio_rt.spawn(async move {
                    let cipher_box = create_cipher_box(algorithm, &key).unwrap();
                    if let Ok(decrypted_chunk) = decrypt_data(cipher_box, chat_msg_proto.encrypted_payload, chat_msg_proto.iv).await {
                        let update = GuiUpdate::FileChunkDecrypted {
                            transfer_id,
                            sequence_number: chat_msg_proto.chunk_sequence_number,
                            data: decrypted_chunk,
                            is_last: chat_msg_proto.is_last_chunk,
                        };
                        gui_tx.send(update).await.ok();
                    }
                });
            }
        } else {
            if let Some(room) = app.active_rooms.get(&room_id) {
                if let Some(key) = app.get_crypto_state(&room_id).and_then(|cs| cs.shared_secret_key_gui.as_ref()) {
                    let key_c = key.clone();
                    let algo_c = room.algorithm;
                    let client_id_for_db_c = app.client_id_for_db.clone();
                    let gui_tx_c = app.gui_update_tx.clone();
                    app.tokio_rt.spawn(async move {
                        message_decryption::decrypt_and_process_message(chat_msg_proto, server_timestamp, key_c, algo_c, client_id_for_db_c, room_id, gui_tx_c).await;
                    });
                }
            }
        }
    }

    fn handle_file_chunk_decrypted(&self, app: &mut SecureMessengerEguiApp, ctx: &egui::Context, transfer_id: String, sequence_number: i32, data: Vec<u8>, is_last: bool) {
        for room in app.active_rooms.values_mut() {
            if let Some(msg) = room.messages.iter_mut().find(|m| m.file_info.as_ref().map_or(false, |fi| fi.transfer_id == transfer_id)) {
                if let Some(fi) = &mut msg.file_info {
                    fi.received_chunks.insert(sequence_number, data);

                    if is_last {
                        let mut full_data = Vec::new();
                        for chunk_data in fi.received_chunks.values() {
                            full_data.extend_from_slice(chunk_data);
                        }
                        fi.decrypted_data = Some(full_data);
                        fi.received_chunks.clear(); 

                        if is_image_filename(&fi.name) {
                            if let Ok(dyn_img) = image::load_from_memory(fi.decrypted_data.as_ref().unwrap()) {
                                let rgba_img = dyn_img.to_rgba8();
                                fi.pending_image_data = Some(PendingImageData {
                                    bytes: rgba_img.into_raw(),
                                    width: dyn_img.width(),
                                    height: dyn_img.height(),
                                });
                                let _ = app.gui_update_tx.try_send(GuiUpdate::NewMessageDecrypted(msg.clone()));
                            }
                        }
                    }
                }
                return; 
            }
        }
    }

    fn handle_key_exchange_data(&self, app: &mut SecureMessengerEguiApp, key_data_proto: messenger_protos::KeyExchangeData) {
        let room_id = key_data_proto.room_id.clone();

        let mut local_keypair_and_algorithm = {
            if let (Some(crypto_state), Some(room)) = (app.get_crypto_state(&room_id), app.active_rooms.get(&room_id)) {
                crypto_state.dh_keypair_gui.as_ref().map(|keypair| (keypair.clone(), room.algorithm))
            } else {
                None
            }
        };


        if local_keypair_and_algorithm.is_none() {
            log::info!("Reactive DH key generation for room {}.", room_id);
            if let Some(room) = app.active_rooms.get(&room_id) {
                self.initiate_dh_key_exchange(app, room.id.clone());
            }

            local_keypair_and_algorithm = {
                if let (Some(crypto_state), Some(room)) = (app.get_crypto_state(&room_id), app.active_rooms.get(&room_id)) {
                    crypto_state.dh_keypair_gui.as_ref().map(|keypair| (keypair.clone(), room.algorithm))
                } else {
                    None
                }
            };
        }

        if let Some((local_keypair, algorithm)) = local_keypair_and_algorithm {
            match compute_shared_secret(&local_keypair.private_key, &key_data_proto.public_key_dh, algorithm) {
                Ok(shared_secret) => {
                    let key_hash = hash_shared_key(&shared_secret); 
                    log::info!("Successfully computed shared secret for room {}. Key hash: {}", room_id, key_hash);

                    if let Some(room) = app.active_rooms.get_mut(&room_id) {
                        if let Some(crypto_state_mut) = app.room_crypto_states.get_mut(&room_id) {
                            crypto_state_mut.shared_secret_key_gui = Some(shared_secret);
                        }

                        let gui_tx_clone = app.gui_update_tx.clone();
                        let room_id_clone = room.id.clone();
                        app.tokio_rt.spawn(async move {
                            gui_tx_clone.send(GuiUpdate::SharedSecretEstablished { room_id: room_id_clone, key_hash }).await.ok();
                            gui_tx_clone.send(GuiUpdate::StatusInfo("Secure channel established!".to_string())).await.ok();
                        });
                    }
                }
                Err(e) => {
                    let gui_tx_clone = app.gui_update_tx.clone();
                    app.tokio_rt.spawn(async move {
                        gui_tx_clone.send(GuiUpdate::LocalError(format!("DH shared secret error: {}", e))).await.ok();
                    });
                }
            }
        } else {
            log::warn!("Received DH key from {}, but could not find a target room for it.", key_data_proto.from_client_id);
        }
    }

    fn handle_room_closed(&self, app: &mut SecureMessengerEguiApp, closed_info: messenger_protos::RoomClosedNotification) {
        log::info!("Received RoomClosed event for room: {}, reason: {}", closed_info.room_id, closed_info.reason);

        app.active_rooms.remove(&closed_info.room_id);
        app.room_crypto_states.remove(&closed_info.room_id);

        if app.current_room_id.as_ref() == Some(&closed_info.room_id) {
            app.current_room_id = None;
            app.current_view = CurrentView::Lobby;
            app.status_message_lobby = format!("Room {} closed: {}", closed_info.room_id, closed_info.reason);
            app.message_input_chat.clear();
            app.selected_file_path = None;
            app.file_op_status.clear();
        } else {
            app.status_message_lobby = format!("Server notice: Room {} closed - {}", closed_info.room_id, closed_info.reason);
        }
    }

    fn handle_server_error(&self, app: &mut SecureMessengerEguiApp, err_notification: messenger_protos::ErrorNotification) {
        let err_msg = format!("Server Error: {}", err_notification.message);
        match app.current_view {
            CurrentView::Lobby => app.status_message_lobby = err_msg,
            CurrentView::Chatting => {
                let gui_tx_clone = app.gui_update_tx.clone();
                app.tokio_rt.spawn(async move {
                    gui_tx_clone.send(GuiUpdate::StatusInfo(err_msg)).await.ok();
                });
            }
            _ => app.connection_status = err_msg,
        }
    }

    fn handle_stream_closed(&self, app: &mut SecureMessengerEguiApp, reason_opt: Option<String>) {
        app.is_connected = false;
        app.to_network_tx = None;
        app.connection_status = format!("Disconnected from server. {}", reason_opt.unwrap_or_default());

        if app.current_view == CurrentView::Chatting {
            app.current_view = CurrentView::Lobby;
            app.status_message_lobby = "Disconnected. Please reconnect.".to_string();
        }

        app.active_rooms.clear();
        app.room_crypto_states.clear();
        app.current_room_id = None;
    }

    fn handle_new_message(&self, app: &mut SecureMessengerEguiApp, ctx: &egui::Context, mut new_msg: crate::state::DecryptedMessageDisplay) {
        if let Some(room) = app.active_rooms.get_mut(&new_msg.room_id) {
            let existing_msg_idx = room.messages.iter().position(|m| m.unique_id == new_msg.unique_id);

            if let Some(file_info) = &mut new_msg.file_info {
                if file_info.data_preview_texture.is_none() {
                    if let Some(pending_data) = file_info.pending_image_data.take() {
                        let color_image = egui::ColorImage::from_rgba_unmultiplied([pending_data.width as usize, pending_data.height as usize], &pending_data.bytes);
                        let texture_name = format!("chat_image_{}_{}", new_msg.unique_id, chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default());
                        let texture_options = egui::TextureOptions::LINEAR;
                        let texture_handle = ctx.load_texture(texture_name, color_image, texture_options);
                        file_info.data_preview_texture = Some(texture_handle);
                        log::debug!("Texture created and set for message_unique_id: {}", new_msg.unique_id);
                    }
                }
            }

            if let Some(idx) = existing_msg_idx {
                if new_msg.file_info.as_ref().map_or(true, |fi| fi.data_preview_texture.is_none()) {
                    if let Some(old_fi) = &room.messages[idx].file_info {
                        if let Some(old_texture) = &old_fi.data_preview_texture {
                            if let Some(new_fi_mut) = &mut new_msg.file_info {
                                new_fi_mut.data_preview_texture = Some(old_texture.clone());
                            }
                        }
                    }
                }

                if new_msg.file_info.as_ref().map_or(true, |fi| fi.decrypted_data.is_none()) {
                    if let Some(old_fi) = &room.messages[idx].file_info {
                        if let Some(old_data) = &old_fi.decrypted_data {
                            if let Some(new_fi_mut) = &mut new_msg.file_info {
                                new_fi_mut.decrypted_data = Some(old_data.clone());
                            }
                        }
                    }
                }

                room.messages[idx] = new_msg;
                log::trace!("Updated existing message in UI: {}", room.messages[idx].unique_id);
            } else {
                room.messages.push(new_msg);
                log::trace!("Added new message to UI. Total messages: {}", room.messages.len());
            }
        }
    }

    fn handle_shared_secret_established(&self, app: &mut SecureMessengerEguiApp, room_id: String, key_hash: String) {
        if let Some(room) = app.active_rooms.get_mut(&room_id) {
            room.is_dh_complete = true;
            room.visual_key_hash = Some(key_hash);
        }
    }

    fn handle_status_update(&self, app: &mut SecureMessengerEguiApp, message: String) {
        match app.current_view {
            CurrentView::Lobby => app.status_message_lobby = message,
            CurrentView::Chatting => app.file_op_status = message,
            _ => app.connection_status = message,
        }
    }

    fn handle_chat_history_loaded(&self, app: &mut SecureMessengerEguiApp, room_id: String, messages: Vec<crate::state::DecryptedMessageDisplay>) {
        if let Some(room) = app.active_rooms.get_mut(&room_id) {
            room.messages = messages;
            app.status_message_lobby = "Chat history loaded.".to_string();
        }
    }

    fn handle_user_leave_room(&self, app: &mut SecureMessengerEguiApp, room_id: String) {
        log::info!("User initiated leave for room: {}", room_id);

        app.active_rooms.remove(&room_id);
        app.room_crypto_states.remove(&room_id);

        if app.current_room_id.as_ref() == Some(&room_id) {
            app.current_room_id = app.active_rooms.keys().next().cloned();

            if app.current_room_id.is_none() {
                app.current_view = CurrentView::Lobby;
            }

            app.status_message_lobby = format!("You have left room {}.", room_id);
            app.message_input_chat.clear();
            app.selected_file_path = None;
            app.file_op_status.clear();
        } else {
            log::warn!("UserInitiatedLeaveRoom for room {} but not currently active in it.", room_id);
        }
    }

    fn handle_file_save_completed(&self, app: &mut SecureMessengerEguiApp, ctx: &egui::Context, message_unique_id: String, saved_path: std::path::PathBuf) {
        for (_, room) in app.active_rooms.iter_mut() {
            if let Some(msg) = room.messages.iter_mut().find(|m| m.unique_id == message_unique_id) {
                if let Some(file_info) = &mut msg.file_info {
                    file_info.path_on_disk = Some(saved_path.clone());
                    file_info.decrypted_data = None; 
                    app.file_op_status = format!("File '{}' saved.", file_info.name);
                    log::info!("Updated message {} with saved path: {}", message_unique_id, saved_path.display());
                    ctx.request_repaint();
                    return;
                }
            }
        }
    }

    fn initiate_dh_key_exchange(&self, app: &mut SecureMessengerEguiApp, room_id: String) {
        let crypto_state = app.get_crypto_state_mut(&room_id);

        if crypto_state.dh_keypair_gui.is_some() {
            log::info!("GUI: DH Key Exchange already initiated or completed for room {}", room_id);
            return;
        }

        log::info!("GUI: Initiating DH Key Exchange for room {}", room_id);

        match generate_dh_keypair() {
            Ok(keypair) => {
                crypto_state.dh_keypair_gui = Some(keypair.clone());

                if let Some(sender) = &app.to_network_tx {
                    let req = ClientRequest {
                        request_id: Uuid::new_v4().to_string(),
                        client_id: app.client_id.clone(),
                        timestamp: chrono::Utc::now().timestamp_millis(),
                        request: Some(ClientRequestType::SendKeyExchange(SendKeyExchangeData {
                            room_id: room_id.clone(),
                            public_key_dh: keypair.public_key.to_bytes_be(),
                        })),
                    };

                    let sender_clone = sender.clone();
                    let gui_tx_clone = app.gui_update_tx.clone();
                    app.tokio_rt.spawn(async move {
                        if let Err(e) = sender_clone.send(req).await {
                            log::error!("Failed to send DH public key: {}", e);
                            gui_tx_clone.send(GuiUpdate::LocalError(format!("Failed to send DH key: {}", e))).await.ok();
                        } else {
                            gui_tx_clone.send(GuiUpdate::StatusInfo(format!("Sent DH public key for room {}.", room_id))).await.ok();
                        }
                    });
                }
            }
            Err(e) => {
                log::error!("Failed to generate DH keypair: {}", e);
                let gui_tx_clone = app.gui_update_tx.clone();
                app.tokio_rt.spawn(async move {
                    gui_tx_clone.send(GuiUpdate::LocalError(format!("Failed to generate DH keypair: {}", e))).await.ok();
                });
            }
        }
    }

    fn load_chat_history(&self, app: &mut SecureMessengerEguiApp, room_id: String) {
        let client_id_for_db_clone = app.client_id_for_db.clone();
        let gui_tx_clone = app.gui_update_tx.clone();
        let rt_handle = app.tokio_rt.handle().clone();

        rt_handle.spawn(async move {
            let db_path = db::ensure_db_path(&client_id_for_db_clone);
            let room_id_for_db_task = room_id.clone();

            let result = tokio::task::spawn_blocking(move || match rusqlite::Connection::open(&db_path) {
                Ok(conn_blocking) => {
                    if let Err(e) = db::execute_schema(&conn_blocking) {
                        return Err(format!("DB Schema creation failed on load: {}", e));
                    }
                    db::load_messages_for_room_db(&conn_blocking, &room_id_for_db_task).map_err(|e| format!("DB Load Error: {}", e))
                }
                Err(e) => Err(format!("DB Connection Error in task: {}", e)),
            })
            .await;

            match result {
                Ok(Ok(msgs)) => {
                    gui_tx_clone.send(GuiUpdate::ChatHistoryLoaded { room_id, messages: msgs }).await.ok();
                }
                Ok(Err(e)) => {
                    gui_tx_clone.send(GuiUpdate::LocalError(e)).await.ok();
                }
                Err(join_err) => {
                    gui_tx_clone.send(GuiUpdate::LocalError(format!("DB task panicked: {}", join_err))).await.ok();
                }
            }
        });
    }
}

pub mod message_decryption {
    use crate::app::SecureMessengerEguiApp;
    use crate::crypto::{create_cipher_box, decrypt_data};
    use crate::db;
    use crate::state::{CurrentView, DecryptedMessageDisplay, FileInfoDisplay, GuiUpdate, PendingImageData};
    use messenger_protos::{ChatMessage, EncryptionAlgorithm as ProtoAlgorithm, PayloadType as ProtoPayloadType};
    use tokio::sync::mpsc;
    use uuid::Uuid;

    pub async fn decrypt_and_process_message(
        chat_msg_proto: ChatMessage,
        server_timestamp: i64,
        key: Vec<u8>,
        algo: ProtoAlgorithm,
        client_id_for_db: String,
        room_id: String,
        gui_tx: mpsc::Sender<GuiUpdate>,
    ) {
        let cipher_algo_box = match create_cipher_box(algo, &key) {
            Ok(cipher) => cipher,
            Err(e) => {
                gui_tx.send(GuiUpdate::LocalError(format!("Failed to create cipher: {}", e))).await.ok();
                return;
            }
        };
    }

    async fn store_message_in_db(mut display_msg: DecryptedMessageDisplay, client_id_for_db: String, gui_tx: mpsc::Sender<GuiUpdate>) {
        let db_path_store = db::ensure_db_path(&client_id_for_db);
        let msg_to_store = display_msg.clone();

        let db_operation_join_handle = tokio::task::spawn_blocking(move || match rusqlite::Connection::open(&db_path_store) {
            Ok(conn) => {
                db::execute_schema(&conn)?;
                db::store_display_message(&conn, &msg_to_store)
            }
            Err(e) => Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN), Some(e.to_string()))),
        });

        match db_operation_join_handle.await {
            Ok(Ok(db_id)) => {
                display_msg.db_id = Some(db_id);
            }
            Ok(Err(db_err)) => {
                gui_tx.send(GuiUpdate::LocalError(format!("DB Store Error: {}", db_err))).await.ok();
            }
            Err(join_err) => {
                gui_tx.send(GuiUpdate::LocalError(format!("DB Store Task Panic: {}", join_err))).await.ok();
            }
        }
    }
}
