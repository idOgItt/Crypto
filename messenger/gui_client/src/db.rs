use super::state::DecryptedMessageDisplay;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Result};
use dirs;
use std::path::PathBuf;

#[derive(Debug)]
pub struct StoredMessageContent {
    pub id: i64,
    pub room_id: String,
    pub sender_id: String,
    pub timestamp_secs: i64,
    pub iv: Option<Vec<u8>>,
    pub decrypted_text_content: Option<String>,
    pub file_name: Option<String>,
    pub local_file_path: Option<String>,
    pub is_outgoing: bool,
}

pub fn ensure_db_path(client_id_for_db: &str) -> String {
    let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let app_data_dir = home_dir.join(".secure_messenger_gui_data");
    std::fs::create_dir_all(&app_data_dir).ok();
    app_data_dir
        .join(format!("{}_chat_history.db", client_id_for_db))
        .to_string_lossy()
        .into_owned()
}

pub fn execute_schema(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            unique_gui_id TEXT NOT NULL UNIQUE,
            room_id TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            timestamp_secs INTEGER NOT NULL,
            iv BLOB,
            content_type TEXT NOT NULL,
            decrypted_text_content TEXT,
            file_name TEXT,
            local_file_path TEXT,
            is_outgoing BOOLEAN NOT NULL
        )",
        [],
    )?;
    Ok(())
}

fn stored_to_display(stored: StoredMessageContent) -> DecryptedMessageDisplay {
    use std::path::PathBuf;
    DecryptedMessageDisplay {
        unique_id: stored.id.to_string(),
        db_id: Some(stored.id),
        room_id: stored.room_id,
        sender_id: stored.sender_id,
        text_content: stored.decrypted_text_content,
        file_info: None,
        timestamp: DateTime::<Utc>::from_timestamp(stored.timestamp_secs, 0).unwrap_or_else(|| Utc::now()),
        is_outgoing: stored.is_outgoing,
        iv_hex: stored.iv.map(hex::encode),
    }
}

pub fn store_display_message(conn: &Connection, msg: &DecryptedMessageDisplay) -> Result<i64> {
    let timestamp_secs = msg.timestamp.timestamp();
    let iv_bytes = msg.iv_hex.as_ref().and_then(|hex_val| hex::decode(hex_val).ok());

    conn.execute(
        "INSERT INTO messages (unique_gui_id, room_id, sender_id, timestamp_secs, iv, content_type, decrypted_text_content, file_name, local_file_path, is_outgoing)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            msg.unique_id,
            msg.room_id,
            msg.sender_id,
            timestamp_secs,
            iv_bytes,
            if msg.file_info.is_some() { "FILE" } else { "TEXT" },
            msg.text_content,
            msg.file_info.as_ref().map(|fi| fi.name.clone()),
            msg.file_info.as_ref().and_then(|fi| fi.path_on_disk.as_ref().map(|p| p.to_string_lossy().into_owned())),
            msg.is_outgoing,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn load_messages_for_room_db(conn: &Connection, room_id_filter: &str) -> Result<Vec<DecryptedMessageDisplay>> {
    let mut stmt = conn.prepare(
        "SELECT id, unique_gui_id, room_id, sender_id, timestamp_secs, iv, content_type, decrypted_text_content, file_name, local_file_path, is_outgoing
         FROM messages WHERE room_id = ?1 ORDER BY timestamp_secs ASC",
    )?;
    let msg_iter = stmt.query_map(params![room_id_filter], |row| {
        Ok(StoredMessageContent {
            id: row.get(0)?,
            room_id: row.get(2)?,
            sender_id: row.get(3)?,
            timestamp_secs: row.get(4)?,
            iv: row.get(5)?,
            decrypted_text_content: row.get(7)?,
            file_name: row.get(8)?,
            local_file_path: row.get(9)?,
            is_outgoing: row.get(10)?,
        })
    })?;

    let mut messages = Vec::new();
    for stored_msg_result in msg_iter {
        messages.push(stored_to_display(stored_msg_result?));
    }
    Ok(messages)
}
