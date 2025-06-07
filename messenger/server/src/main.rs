use messenger_protos::MessengerServiceServer;
use server::chat_manager::ChatManager;
use server::service::SecureMessengerService;
use std::sync::Arc;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    log::info!("Starting Secure Messenger Server...");

    let addr = "0.0.0.0:50051".parse()?;
    let chat_manager = Arc::new(ChatManager::new());
    let messenger_service = SecureMessengerService::new(chat_manager);

    log::info!("Server listening on {}", addr);

    Server::builder()
        .add_service(MessengerServiceServer::new(messenger_service))
        .serve(addr)
        .await?;

    Ok(())
}
