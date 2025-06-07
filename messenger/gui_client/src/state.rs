use egui::TextureHandle;
use messenger_protos::EncryptionAlgorithm as ProtoAlgorithm;
use std::path::PathBuf;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum CurrentView {
    Connection,
    Lobby,
    Chatting,
}

pub struct RoomState {
    pub id: String,
    pub algorithm: ProtoAlgorithm,
    pub participants: Vec<String>,
    pub messages: Vec<DecryptedMessageDisplay>,
    pub is_dh_complete: bool,
    pub visual_key_hash: Option<String>,
}

#[derive(Clone)]
pub struct DecryptedMessageDisplay {
    pub unique_id: String,
    pub db_id: Option<i64>,
    pub room_id: String,
    pub sender_id: String,
    pub text_content: Option<String>,
    pub file_info: Option<FileInfoDisplay>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub is_outgoing: bool,
    pub iv_hex: Option<String>,
}

#[derive(Clone)]
pub struct FileInfoDisplay {
    pub name: String,
    pub path_on_disk: Option<PathBuf>,
    pub data_preview_texture: Option<TextureHandle>,
    pub pending_image_data: Option<PendingImageData>,
    pub decrypted_data: Option<Vec<u8>>,
    pub transfer_id: String,
    pub transfer_progress: f32,
    pub is_download: bool,
    pub received_chunks: BTreeMap<i32, Vec<u8>>,
    pub transfer_cancelled: bool,
}

#[derive(Clone)]
pub struct PendingImageData {
    pub bytes: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

pub enum GuiUpdate {
    ConnectionAttemptResult(Result<(), String>),
    ServerMessageReceived(messenger_protos::ServerMessage),
    GrpcStreamClosed(Option<String>),

    FileTransferProgress {
        transfer_id: String,
        progress: f32,
    },
    FileTransferFinished {
        transfer_id: String,
    },
    FileTransferCancelled {
        transfer_id: String,
    },
    FileChunkDecrypted {
        transfer_id: String,
        sequence_number: i32,
        data: Vec<u8>,
        is_last: bool,
    },
    NewMessageDecrypted(DecryptedMessageDisplay),
    SharedSecretEstablished {
        room_id: String,
        key_hash: String,
    },
    LocalError(String),
    StatusInfo(String),
    ChatHistoryLoaded {
        room_id: String,
        messages: Vec<DecryptedMessageDisplay>,
    },
    FileSelectedForSending(PathBuf),
    UserInitiatedLeaveRoom(String),
    FileSaveCompleted {
        message_unique_id: String,
        saved_path: PathBuf,
    },
}
