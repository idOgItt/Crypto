use eframe::egui::{self, CentralPanel, Color32, RichText, SidePanel};
use uuid::Uuid;

use crate::SecureMessengerEguiApp;
use messenger_protos::{ClientRequest, ClientRequestType, CreateRoomRequest, EncryptionAlgorithm as ProtoAlgorithm, JoinRoomRequest};

pub struct LobbyView;

impl LobbyView {
    pub fn draw(app: &mut SecureMessengerEguiApp, ctx: &egui::Context) {
        SidePanel::left("chat_list_panel").default_width(200.0).show(ctx, |ui| {
            ui.heading("Active Chats");
            ui.separator();

            if app.active_rooms.is_empty() {
                ui.label("No active chats");
            } else {
                let room_ids: Vec<String> = app.active_rooms.keys().cloned().collect();

                for room_id in room_ids {
                    let (is_selected, is_dh_complete, participant_count) = {
                        let room_state = app.active_rooms.get(&room_id).unwrap();
                        (app.current_room_id.as_ref() == Some(&room_id), room_state.is_dh_complete, room_state.participants.len())
                    };

                    ui.horizontal(|ui| {
                        if is_dh_complete {
                            ui.colored_label(Color32::GREEN, "🔒");
                        } else {
                            ui.colored_label(Color32::YELLOW, "🔓");
                        }

                        let label = format!("Room: {}", &room_id[..8.min(room_id.len())]);
                        if ui.selectable_label(is_selected, label).clicked() {
                            app.switch_to_room(room_id.clone());
                        }
                    });

                    ui.add_space(2.0);
                    ui.label(RichText::new(format!("  {} participants", participant_count)).small().weak());
                    ui.separator();
                }
            }
        });

        CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("Lobby");
                ui.label(&app.status_message_lobby);
                ui.add_space(20.0);

                Self::draw_join_room(app, ui);
                ui.add_space(20.0);
                Self::draw_create_room(app, ui);
            });
        });
    }

    fn draw_join_room(app: &mut SecureMessengerEguiApp, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Room ID to Join:");
            ui.text_edit_singleline(&mut app.room_id_input);

            if ui.button("Join Room").clicked() && !app.room_id_input.is_empty() {
                if let Some(sender) = &app.to_network_tx {
                    let req = ClientRequest {
                        request_id: Uuid::new_v4().to_string(),
                        client_id: app.client_id.clone(),
                        timestamp: chrono::Utc::now().timestamp_millis(),
                        request: Some(ClientRequestType::JoinRoom(JoinRoomRequest { room_id: app.room_id_input.clone() })),
                    };

                    let sender_clone = sender.clone();
                    app.tokio_rt.spawn(async move {
                        if let Err(e) = sender_clone.send(req).await {
                            log::error!("Failed to send JoinRoom req: {}", e);
                        }
                    });

                    app.status_message_lobby = format!("Attempting to join room {}...", app.room_id_input);
                }
            }
        });
    }

    fn draw_create_room(app: &mut SecureMessengerEguiApp, ui: &mut egui::Ui) {
        ui.label("Create New Room:");

        egui::ComboBox::from_label("Encryption Algorithm")
            .selected_text(format!("{:?}", app.selected_algorithm_lobby))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut app.selected_algorithm_lobby, ProtoAlgorithm::Loki97, "LOKI97");
                ui.selectable_value(&mut app.selected_algorithm_lobby, ProtoAlgorithm::Twofish, "TWOFISH");
            });

        if ui.button("Create Room").clicked() {
            if let Some(sender) = &app.to_network_tx {
                let req = ClientRequest {
                    request_id: Uuid::new_v4().to_string(),
                    client_id: app.client_id.clone(),
                    timestamp: chrono::Utc::now().timestamp_millis(),
                    request: Some(ClientRequestType::CreateRoom(CreateRoomRequest {
                        algorithm: app.selected_algorithm_lobby as i32,
                    })),
                };

                let sender_clone = sender.clone();
                app.tokio_rt.spawn(async move {
                    if let Err(e) = sender_clone.send(req).await {
                        log::error!("Failed to send CreateRoom req: {}", e);
                    }
                });

                app.status_message_lobby = format!("Attempting to create room with {:?}...", app.selected_algorithm_lobby);
            }
        }
    }
}
