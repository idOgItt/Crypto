#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod crypto;
mod db;
mod handlers;
mod messages;
mod network;
mod state;
mod ui;

use app::SecureMessengerEguiApp;

fn main() -> Result<(), eframe::Error> {
    env_logger::init(); 
    log::info!("Starting Secure Messenger GUI client...");

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([900.0, 700.0]).with_min_inner_size([600.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native("Secure Messenger", options, Box::new(|cc| Box::new(SecureMessengerEguiApp::new(cc))))
}
