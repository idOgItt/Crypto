use crate::SecureMessengerEguiApp;
use eframe::egui::{self, CentralPanel};

pub struct ConnectionView;

impl ConnectionView {
    pub fn draw(app: &mut SecureMessengerEguiApp, ctx: &egui::Context) {
        CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("Secure Messenger");
                ui.add_space(20.0);
                ui.label("Server Address:");
                ui.text_edit_singleline(&mut app.server_address_input);

                if ui.button("Connect").clicked() {
                    app.handle_connect();
                }

                ui.add_space(10.0);
                ui.label(&app.connection_status);
            });
        });
    }
}
