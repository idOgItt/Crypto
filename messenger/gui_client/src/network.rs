use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;

use crate::state::GuiUpdate;
use messenger_protos::{ClientRequest, MessengerServiceClient};

pub struct NetworkEventLoop {
    client_id: String,
    server_address: String,
    from_gui_rx: mpsc::Receiver<ClientRequest>,
    to_gui_tx: mpsc::Sender<GuiUpdate>,
}

impl NetworkEventLoop {
    pub fn new(
        client_id: String,
        server_address: String,
        from_gui_rx: mpsc::Receiver<ClientRequest>,
        to_gui_tx: mpsc::Sender<GuiUpdate>,
    ) -> Self {
        Self {
            client_id,
            server_address,
            from_gui_rx,
            to_gui_tx,
        }
    }

    pub async fn run(self) {
        log::info!(
            "NetworkEventLoop for client {} starting for server {}",
            self.client_id,
            self.server_address
        );

        match MessengerServiceClient::connect(self.server_address.clone()).await {
            Ok(mut client) => {
                log::info!(
                    "Successfully connected to gRPC server: {}",
                    self.server_address
                );
                self.to_gui_tx
                    .send(GuiUpdate::ConnectionAttemptResult(Ok(())))
                    .await
                    .ok();

                let request_stream = ReceiverStream::new(self.from_gui_rx);

                match client.chat_stream(Request::new(request_stream)).await {
                    Ok(response) => {
                        log::info!("ChatStream established.");
                        let mut server_message_stream = response.into_inner();

                        while let Some(result) = server_message_stream.next().await {
                            match result {
                                Ok(server_msg) => {
                                    if self
                                        .to_gui_tx
                                        .send(GuiUpdate::ServerMessageReceived(server_msg))
                                        .await
                                        .is_err()
                                    {
                                        log::warn!("GUI receiver closed for ServerMessageReceived. Shutting down network loop.");
                                        break;
                                    }
                                }
                                Err(status) => {
                                    log::error!("Error from server stream: {}", status);
                                    self.to_gui_tx
                                        .send(GuiUpdate::GrpcStreamClosed(Some(format!(
                                            "Server stream error: {}",
                                            status
                                        ))))
                                        .await
                                        .ok();
                                    break;
                                }
                            }
                        }
                    }
                    Err(status) => {
                        log::error!("Failed to establish ChatStream: {}", status);
                        self.to_gui_tx
                            .send(GuiUpdate::ConnectionAttemptResult(Err(format!(
                                "ChatStream setup failed: {}",
                                status
                            ))))
                            .await
                            .ok();
                    }
                }
            }
            Err(e) => {
                log::error!(
                    "Failed to connect to gRPC server {}: {}",
                    self.server_address,
                    e
                );
                self.to_gui_tx
                    .send(GuiUpdate::ConnectionAttemptResult(Err(format!(
                        "Connection failed: {}",
                        e
                    ))))
                    .await
                    .ok();
            }
        }

        log::info!("NetworkEventLoop for client {} ended.", self.client_id);

        self.to_gui_tx
            .send(GuiUpdate::GrpcStreamClosed(None))
            .await
            .ok();
    }
}