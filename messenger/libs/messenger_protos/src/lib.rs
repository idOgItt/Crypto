// This will export the generated_code module
// The generated code will be in a messenger.rs file (or similar) in OUT_DIR
// and included via a macro like tonic::include_proto!("messenger");

// The types will be available under the 'messenger' module, e.g., messenger::ClientRequest
pub mod messenger {
    tonic::include_proto!("messenger"); // Matches the package name in .proto
}

// Optionally re-export for convenience
pub use messenger::{
    client_request::Request as ClientRequestType,
    messenger_service_client::MessengerServiceClient,
    messenger_service_server::{MessengerService, MessengerServiceServer},
    server_message::Event as ServerEventType,
    ChatMessage, ClientRequest, CreateRoomRequest, EncryptionAlgorithm, ErrorNotification,
    JoinRoomRequest, KeyExchangeData, LeaveRoomRequest, PayloadType, RoomClosedNotification,
    RoomInfo, SendKeyExchangeData, SendMessageRequest, ServerAck, ServerMessage, UserStatusUpdate,
};
