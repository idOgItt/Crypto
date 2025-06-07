use eframe::egui::{self, Align, CentralPanel, Color32, Frame, Layout, RichText, ScrollArea, SidePanel, TextEdit, TopBottomPanel};
use uuid::Uuid;

use crate::messages::MessageSender;
use crate::state::GuiUpdate;
use crate::{ui::is_image_filename, SecureMessengerEguiApp};
use messenger_protos::{ClientRequest, ClientRequestType, LeaveRoomRequest};

pub struct ChatView;

impl ChatView {
    pub fn draw(app: &mut SecureMessengerEguiApp, ctx: &egui::Context) {
        Self::draw_chat_list(app, ctx);

        if let Some(current_room_id) = app.current_room_id.clone() {
            if let Some(mut room_state) = app.active_rooms.remove(&current_room_id) {
                Self::draw_top_panel(app, ctx, &room_state);
                Self::draw_messages(app, ctx, &mut room_state);
                Self::draw_input_panel(app, ctx, &room_state);
                app.active_rooms.insert(current_room_id, room_state);
            }
        }
    }

    fn draw_chat_list(app: &mut SecureMessengerEguiApp, ctx: &egui::Context) {
        SidePanel::left("chat_list_panel_in_chat").default_width(200.0).show(ctx, |ui| {
            ui.heading("Active Chats");
            ui.separator();

            if ui.button("← Back to Lobby").clicked() {
                app.current_view = crate::state::CurrentView::Lobby;
            }
            ui.separator();

            let room_ids: Vec<String> = app.active_rooms.keys().cloned().collect();

            for room_id in room_ids {
                let (is_selected, is_dh_complete, last_message_preview) = {
                    let room_state = app.active_rooms.get(&room_id).unwrap();
                    let is_selected = app.current_room_id.as_ref() == Some(&room_id);
                    let is_dh_complete = room_state.is_dh_complete;

                    let preview = if let Some(last_msg) = room_state.messages.last() {
                        if let Some(text) = &last_msg.text_content {
                            format!("{}: {}", &last_msg.sender_id[..6.min(last_msg.sender_id.len())], &text[..20.min(text.len())])
                        } else if last_msg.file_info.is_some() {
                            format!("{}: [File]", &last_msg.sender_id[..6.min(last_msg.sender_id.len())])
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };

                    (is_selected, is_dh_complete, preview)
                };

                ui.horizontal(|ui| {
                    if is_dh_complete {
                        ui.colored_label(Color32::GREEN, "🔒");
                    } else {
                        ui.colored_label(Color32::YELLOW, "🔓");
                    }

                    let label = format!("Room: {}", &room_id[..8.min(room_id.len())]);
                    if ui.selectable_label(is_selected, label).clicked() {
                        app.current_room_id = Some(room_id.clone());
                        app.message_input_chat.clear();
                        app.selected_file_path = None;
                        app.file_op_status.clear();
                    }
                });

                if !last_message_preview.is_empty() {
                    ui.label(RichText::new(last_message_preview).small().weak());
                }

                ui.separator();
            }
        });
    }

    fn draw_top_panel(app: &mut SecureMessengerEguiApp, _ctx: &egui::Context, room_state: &crate::state::RoomState) {
        TopBottomPanel::top("chat_top_panel").show(_ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading(format!("Chat Room: {}", room_state.id));
                ui.label(format!("(Algo: {:?})", room_state.algorithm));

                if ui.button("Leave Room").clicked() {
                    Self::handle_leave_room(app, room_state);
                }
            });

            ui.label(format!("Participants: {:?}", room_state.participants));

            if room_state.is_dh_complete {
                ui.horizontal(|ui| {
                    ui.colored_label(Color32::GREEN, "✅ Secure channel established.");
                    if let Some(hash) = &room_state.visual_key_hash {
                        ui.label(format!("Key Fingerprint:"));
                        ui.label(RichText::new(hash).monospace().strong());
                    }
                });
            } else {
                ui.colored_label(Color32::YELLOW, "🔓 Warning: Secure key exchange not yet complete.");
            }
        });
    }

    fn draw_messages(app: &mut SecureMessengerEguiApp, ctx: &egui::Context, room_state: &mut crate::state::RoomState) {
        CentralPanel::default().show(ctx, |ui| {
            ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
                for msg in &room_state.messages {
                    Self::draw_message(app, ui, msg);
                }
            });
        });
    }

    fn draw_message(app: &mut SecureMessengerEguiApp, ui: &mut egui::Ui, msg: &crate::state::DecryptedMessageDisplay) {
        ui.add_space(5.0);

        let layout_align = if msg.is_outgoing { Align::Max } else { Align::Min };
        let frame_margin = egui::Margin {
            left: if msg.is_outgoing { ui.available_width() * 0.2 } else { 0.0 },
            right: if !msg.is_outgoing { ui.available_width() * 0.2 } else { 0.0 },
            top: 2.0,
            bottom: 2.0,
        };

        ui.with_layout(Layout::top_down(layout_align), |ui| {
            Frame::group(ui.style())
                .inner_margin(egui::Margin::same(5.0))
                .outer_margin(frame_margin)
                .rounding(egui::Rounding::same(5.0))
                .fill(if msg.is_outgoing { Color32::from_rgb(50, 80, 120) } else { Color32::from_rgb(70, 70, 70) })
                .show(ui, |ui| {
                    ui.set_max_width(ui.available_width() * 0.8);
                    ui.vertical(|ui| {
                        Self::draw_message_header(ui, msg);

                        if let Some(text) = &msg.text_content {
                            ui.label(text);
                        }

                        if let Some(file_info) = &msg.file_info {
                            Self::draw_file_info(app, ui, msg, file_info);
                        }
                    });
                });
        });
    }

    fn draw_message_header(ui: &mut egui::Ui, msg: &crate::state::DecryptedMessageDisplay) {
        ui.horizontal(|ui| {
            ui.label(RichText::new(&msg.sender_id).small().strong());
            ui.label(RichText::new(msg.timestamp.format("%H:%M:%S").to_string()).small().weak());

            if let Some(iv_hex_short) = msg.iv_hex.as_ref().map(|s| s.chars().take(4).collect::<String>()) {
                ui.label(RichText::new(format!("IV: {}..", iv_hex_short)).small().monospace().weak());
            }
        });
    }

    fn draw_file_info(app: &mut SecureMessengerEguiApp, ui: &mut egui::Ui, msg: &crate::state::DecryptedMessageDisplay, file_info: &crate::state::FileInfoDisplay) {
        ui.vertical(|ui| {
            ui.label(format!("File: {}", file_info.name));
            ui.add_space(2.0);

            if is_image_filename(&file_info.name) {
                Self::draw_image_preview(ui, file_info);
            }

            Self::draw_download_button(app, ui, msg, file_info);

            if !file_info.is_download && file_info.transfer_progress < 1.0 && !file_info.transfer_cancelled {
                ui.add(egui::ProgressBar::new(file_info.transfer_progress).show_percentage());

                if ui.button("Cancel").clicked() {
                    if let Some(handle) = app.active_transfers.remove(&file_info.transfer_id) {
                        handle.abort();
                        let gui_tx = app.gui_update_tx.clone();
                        let transfer_id = file_info.transfer_id.clone();
                        app.tokio_rt.spawn(async move {
                            gui_tx.send(GuiUpdate::FileTransferCancelled { transfer_id }).await.ok();
                        });
                    }
                }
            }

            if file_info.transfer_cancelled {
                ui.colored_label(Color32::YELLOW, "Upload cancelled.");
            }
        });
    }

    fn draw_image_preview(ui: &mut egui::Ui, file_info: &crate::state::FileInfoDisplay) {
        if let Some(texture_handle) = &file_info.data_preview_texture {
            let max_size = egui::vec2(150.0, 150.0);
            let image_widget = egui::Image::new(texture_handle)
                .max_size(max_size)
                .rounding(egui::Rounding::same(4.0))
                .bg_fill(ui.style().visuals.widgets.inactive.bg_fill);
            ui.add(image_widget);
            ui.add_space(4.0);
        } else {
            ui.label(RichText::new("[Image preview loading...]").italics().weak());
            ui.add_space(4.0);
        }
    }

    fn draw_download_button(app: &mut SecureMessengerEguiApp, ui: &mut egui::Ui, msg: &crate::state::DecryptedMessageDisplay, file_info: &crate::state::FileInfoDisplay) {
        if let Some(path_on_disk) = &file_info.path_on_disk {
            ui.label(format!("Saved to: {}", path_on_disk.display()));
        } else if file_info.decrypted_data.is_some() {
            if ui
                .add(egui::Button::new(format!("💾 Download {}", file_info.name)).small())
                .on_hover_text("Click to save this file")
                .clicked()
            {
                Self::handle_download_file(app, msg, file_info);
            }
        } else {
            ui.label(RichText::new("[File not downloaded]").italics().weak());
        }
    }

    fn draw_input_panel(app: &mut SecureMessengerEguiApp, ctx: &egui::Context, room_state: &crate::state::RoomState) {
        TopBottomPanel::bottom("chat_input_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let response = TextEdit::singleline(&mut app.message_input_chat)
                    .hint_text("Type a message...")
                    .desired_width(ui.available_width() - 120.0)
                    .show(ui);

                if ui.button("Attach").on_hover_text("Attach a file").clicked() {
                    Self::handle_attach_file(app);
                }

                if app.selected_file_path.is_some() {
                    ui.label(format!("Selected: {}", app.selected_file_path.as_ref().unwrap().file_name().unwrap_or_default().to_string_lossy()));
                }

                if ui.button("Send").clicked() || (response.response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                    if !app.message_input_chat.is_empty() || app.selected_file_path.is_some() {
                        MessageSender::send_message(app, room_state);
                    }
                }
            });
            ui.label(&app.file_op_status);
        });
    }

    fn handle_leave_room(app: &mut SecureMessengerEguiApp, room_state: &crate::state::RoomState) {
        if let Some(sender) = &app.to_network_tx {
            let room_id_to_leave = room_state.id.clone();
            let req = ClientRequest {
                request_id: Uuid::new_v4().to_string(),
                client_id: app.client_id.clone(),
                timestamp: chrono::Utc::now().timestamp_millis(),
                request: Some(ClientRequestType::LeaveRoom(LeaveRoomRequest { room_id: room_id_to_leave.clone() })),
            };

            let sender_clone = sender.clone();
            let gui_update_tx_clone = app.gui_update_tx.clone();

            app.tokio_rt.spawn(async move {
                if let Err(e) = sender_clone.send(req).await {
                    log::error!("Failed to send LeaveRoom req: {}", e);
                    let _ = gui_update_tx_clone.send(GuiUpdate::LocalError(format!("Failed to send leave request: {}", e))).await;
                } else {
                    log::info!("LeaveRoom request successfully sent for room {}", room_id_to_leave);
                    let _ = gui_update_tx_clone.send(GuiUpdate::UserInitiatedLeaveRoom(room_id_to_leave)).await;
                }
            });
        }
    }

    fn handle_attach_file(app: &mut SecureMessengerEguiApp) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let rt_handle = app.tokio_rt.handle().clone();
            let gui_update_tx_clone = app.gui_update_tx.clone();
            rt_handle.spawn(async move {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    gui_update_tx_clone.send(GuiUpdate::FileSelectedForSending(path)).await.ok();
                }
            });
        }
    }

    fn handle_download_file(app: &mut SecureMessengerEguiApp, msg: &crate::state::DecryptedMessageDisplay, file_info: &crate::state::FileInfoDisplay) {
        if let Some(data_to_save) = file_info.decrypted_data.as_ref().cloned() {
            let file_name_clone = file_info.name.clone();
            let message_unique_id_clone = msg.unique_id.clone();
            let rt_handle_clone = app.tokio_rt.handle().clone();
            let gui_update_tx_clone = app.gui_update_tx.clone();

            rt_handle_clone.spawn(async move {
                if let Some(path) = rfd::FileDialog::new().set_file_name(&file_name_clone).save_file() {
                    match tokio::fs::write(&path, &data_to_save).await {
                        Ok(_) => {
                            log::info!("File '{}' saved to {}", file_name_clone, path.display());
                            gui_update_tx_clone
                                .send(GuiUpdate::FileSaveCompleted {
                                    message_unique_id: message_unique_id_clone,
                                    saved_path: path,
                                })
                                .await
                                .ok();
                        }
                        Err(e) => {
                            log::error!("Failed to save file '{}': {}", file_name_clone, e);
                            gui_update_tx_clone.send(GuiUpdate::LocalError(format!("Failed to save file: {}", e))).await.ok();
                        }
                    }
                } else {
                    log::info!("File save cancelled by user for {}", file_name_clone);
                }
            });
        } else {
            log::warn!("Download clicked but decrypted_data was None unexpectedly for {}", file_info.name);
            let gui_update_tx_clone = app.gui_update_tx.clone();
            let error_msg = "Error: File data not available for download.".to_string();
            app.tokio_rt.spawn(async move {
                gui_update_tx_clone.send(GuiUpdate::LocalError(error_msg)).await.ok();
            });
        }
    }
}
