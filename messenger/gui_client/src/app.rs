use eframe::{egui, App};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use uuid::Uuid;

use crate::crypto::CryptoState;
use crate::handlers::UpdateHandler;
use crate::network::NetworkEventLoop;
use crate::state::{CurrentView, GuiUpdate, RoomState};
use crate::ui::{ChatView, ConnectionView, LobbyView};

use messenger_protos::{ClientRequest, EncryptionAlgorithm as ProtoAlgorithm};

pub struct SecureMessengerEguiApp {
    pub client_id: String,
    pub client_id_for_db: String,
    pub current_view: CurrentView,
    pub tokio_rt: Arc<Runtime>,
    pub server_address_input: String,
    pub connection_status: String,
    pub is_connected: bool,
    pub room_id_input: String,
    pub selected_algorithm_lobby: ProtoAlgorithm,
    pub status_message_lobby: String,
    pub active_rooms: HashMap<String, RoomState>,
    pub current_room_id: Option<String>,
    pub message_input_chat: String,
    pub selected_file_path: Option<PathBuf>,
    pub file_op_status: String,
    pub room_crypto_states: HashMap<String, CryptoState>,
    pub to_network_tx: Option<mpsc::Sender<ClientRequest>>,
    pub from_network_rx: mpsc::Receiver<GuiUpdate>,
    pub gui_update_tx: mpsc::Sender<GuiUpdate>,
    pub active_transfers: HashMap<String, AbortHandle>,
}

impl SecureMessengerEguiApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let client_id = Uuid::new_v4().to_string();
        let (gui_update_tx, from_network_rx) = mpsc::channel(128);
        let client_id_for_db = client_id.replace("-", "_");

        Self {
            client_id,
            client_id_for_db,
            current_view: CurrentView::Connection,
            tokio_rt: Arc::new(Runtime::new().expect("Failed to create Tokio runtime")),
            server_address_input: "http://127.0.0.1:50051".to_string(),
            connection_status: "Not Connected".to_string(),
            is_connected: false,
            room_id_input: String::new(),
            selected_algorithm_lobby: ProtoAlgorithm::Loki97,
            status_message_lobby: String::new(),
            active_rooms: HashMap::new(),
            current_room_id: None,
            message_input_chat: String::new(),
            room_crypto_states: HashMap::new(),
            to_network_tx: None,
            from_network_rx,
            gui_update_tx,
            selected_file_path: None,
            file_op_status: String::new(),
            active_transfers: HashMap::new(),
        }
    }

    pub fn handle_connect(&mut self) {
        if !self.is_connected {
            self.connection_status = format!("Connecting to {}...", self.server_address_input);
            let (to_net_tx, from_gui_rx_for_net) = mpsc::channel(128);
            self.to_network_tx = Some(to_net_tx);

            let network_loop = NetworkEventLoop::new(
                self.client_id.clone(),
                self.server_address_input.clone(),
                from_gui_rx_for_net,
                self.gui_update_tx.clone(),
            );
            self.tokio_rt.spawn(network_loop.run());
        }
    }

    pub fn get_crypto_state(&self, room_id: &str) -> Option<&CryptoState> {
        self.room_crypto_states.get(room_id)
    }

    pub fn get_crypto_state_mut(&mut self, room_id: &str) -> &mut CryptoState {
        self.room_crypto_states.entry(room_id.to_string()).or_insert_with(CryptoState::new)
    }

    pub fn switch_to_room(&mut self, room_id: String) {
        self.current_room_id = Some(room_id);
        self.current_view = CurrentView::Chatting;
        self.message_input_chat.clear();
        self.selected_file_path = None;
        self.file_op_status.clear();
    }
}

impl App for SecureMessengerEguiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let update_handler = UpdateHandler::new();
        while let Ok(update) = self.from_network_rx.try_recv() {
            update_handler.handle_update(self, ctx, update);
        }

        match self.current_view {
            CurrentView::Connection => ConnectionView::draw(self, ctx),
            CurrentView::Lobby => LobbyView::draw(self, ctx),
            CurrentView::Chatting => {
                if self.current_room_id.is_some() {
                    ChatView::draw(self, ctx);
                } else {
                    log::warn!("In Chatting view but current_room_id is None. Switching to Lobby.");
                    self.current_view = CurrentView::Lobby;
                    LobbyView::draw(self, ctx);
                }
            }
        }

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}
