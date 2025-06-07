mod chat_view;
mod connection_view;
mod lobby_view;

pub use chat_view::ChatView;
pub use connection_view::ConnectionView;
pub use lobby_view::LobbyView;

pub fn is_image_filename(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.ends_with(".png") || lower.ends_with(".jpg") || lower.ends_with(".jpeg") || lower.ends_with(".gif") || lower.ends_with(".bmp")
}
